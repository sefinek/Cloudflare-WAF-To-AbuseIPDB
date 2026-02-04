//   Copyright 2024-2026 © by Sefinek. All Rights Reserved.
//                   https://sefinek.net

const { CronJob } = require('cron');
const banner = require('./scripts/banners/cloudflare.js');
const { repoSlug, repoUrl } = require('./scripts/repo.js');
const { axiosService, axiosCloudflare } = require('./scripts/services/axios.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const ABUSE_STATE = require('./scripts/services/state.js');
const PAYLOAD = require('./scripts/services/cloudflare/generateFirewallQuery.js');
const SefinekAPI = require('./scripts/services/cloudflare/reportToSefinek.js');
const { logToCSV, readReportedIPs } = require('./scripts/services/cloudflare/csv.js');
const getFilters = require('./scripts/services/cloudflare/getFilterRules.js');
require('./scripts/cliHelp.js');
const logger = require('./scripts/logger.js');
const { MAIN, GENERATE_COMMENT } = require('./config.js');
const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;
let cycleId = 1;

const nextRateLimitReset = () => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
};

let LAST_RATELIMIT_LOG = 0, LAST_STATS_LOG = 0, RATELIMIT_RESET = nextRateLimitReset();

const checkRateLimit = async () => {
	const now = Date.now();
	if (now - LAST_STATS_LOG >= BUFFER_STATS_INTERVAL && BULK_REPORT_BUFFER.size > 0) LAST_STATS_LOG = now;

	if (ABUSE_STATE.isLimited) {
		if (now >= RATELIMIT_RESET.getTime()) {
			ABUSE_STATE.isLimited = false;
			ABUSE_STATE.isBuffering = false;
			if (!ABUSE_STATE.sentBulk && BULK_REPORT_BUFFER.size > 0) await sendBulkReport();
			RATELIMIT_RESET = nextRateLimitReset();
			ABUSE_STATE.sentBulk = false;
			logger.success(`Rate limit reset. Next reset scheduled at \`${RATELIMIT_RESET.toISOString()}\`.`, { discord: true });
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			logger.success(`Rate limit is still active, collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})...`);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const fetchCloudflareEvents = async whitelist => {
	if (MAIN.CLOUDFLARE_ZONE_IDS && MAIN.CLOUDFLARE_ZONE_ID) {
		logger.info('Both CLOUDFLARE_ZONE_IDS and deprecated CLOUDFLARE_ZONE_ID are defined. Using CLOUDFLARE_ZONE_IDS.');
	}

	const rawZoneIds = MAIN.CLOUDFLARE_ZONE_IDS || MAIN.CLOUDFLARE_ZONE_ID;
	const zoneIds = Array.isArray(rawZoneIds) ? rawZoneIds : [rawZoneIds];
	const allEvents = [];

	for (const zoneId of zoneIds) {
		try {
			const { data, status } = await axiosCloudflare.post('/graphql', PAYLOAD(zoneId));

			const events = data?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive;
			if (!events) throw new Error(`Failed to retrieve data from Cloudflare (status ${status}): ${JSON.stringify(data?.errors)}`);

			allEvents.push(...events);
		} catch (err) {
			logger.error(err.response?.data ? `${err.response.status} HTTP ERROR for zone ${zoneId}: ${JSON.stringify(err.response.data, null, 2)}` : `Unknown error for zone ${zoneId}: ${err.message}`);
		}
	}

	const isWhitelisted = event =>
		getServerIPs().includes(event.clientIP) ||
		whitelist.userAgents?.some(ua => event.userAgent?.includes(ua)) ||
		whitelist.imgExtensions?.some(ext => event.clientRequestPath?.endsWith(ext)) ||
		whitelist.domains?.some(domain => event.clientRequestHTTPHost?.includes(domain)) ||
		whitelist.endpoints?.some(endpoint => event.clientRequestPath?.includes(endpoint));

	const allowAllSources = !Array.isArray(MAIN.ALLOWED_SOURCES) || !MAIN.ALLOWED_SOURCES.length;
	const allowedSources = allowAllSources ? null : new Set(MAIN.ALLOWED_SOURCES.map(s => String(s).toLowerCase()));

	const filtered = allEvents.filter(event => {
		const src = String(event.source || '').toLowerCase();
		if (!allowAllSources && !allowedSources.has(src)) return false;
		return src === 'l7ddos' ? true : !isWhitelisted(event);
	});

	const stats = allEvents.reduce((acc, ev) => {
		const src = String(ev.source || '').toLowerCase();
		const isAllowed = allowAllSources || allowedSources?.has(src);
		acc[isAllowed ? src : `${src} (ignored)`] = (acc[isAllowed ? src : `${src} (ignored)`] || 0) + 1;
		return acc;
	}, {});
	const statsStr = Object.entries(stats).map(([src, cnt]) => `${src}: ${cnt}`).join(', ');

	logger.success(`Fetched ${allEvents.length} Cloudflare events [${filtered.length} matching filter criteria]${allowAllSources ? ' [no source filtering]' : ''} [${statsStr}]`);
	return filtered;
};

const reportIP = async (event, categories, comment) => {
	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (!BULK_REPORT_BUFFER.has(event.clientIP)) {
			BULK_REPORT_BUFFER.set(event.clientIP, { categories, timestamp: event.datetime, comment });
			await saveBufferToFile();
			logger.success(`Queued ${event.clientIP} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs, source: ${event.source})`);
			return { success: false, code: 'READY_FOR_BULK_REPORT' };
		}
		return { success: false, code: 'ALREADY_IN_BUFFER' };
	}

	try {
		await axiosService.post('/report', {
			ip: event.clientIP,
			categories,
			comment,
			timestamp: event.datetime,
		});

		logger.success(`Reported ${event.clientIP} >> ${event.clientRequestPath} << ${event.source}`);
		return { success: true, code: 'REPORTED' };
	} catch (err) {
		const status = err.response?.status ?? 'unknown';
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				logger.info(`Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toLocaleString()}`, { discord: true });
			}

			if (!BULK_REPORT_BUFFER.has(event.clientIP)) {
				BULK_REPORT_BUFFER.set(event.clientIP, { timestamp: event.datetime, categories, comment });
				await saveBufferToFile();
				logger.success(`Queued ${event.clientIP} for bulk report due to rate limit`);
				return { success: false, code: 'RL_BULK_REPORT' };
			}

			return { success: false, code: 'ALREADY_IN_BUFFER' };
		}

		status === 429
			? logger.info(`Error    ${event.clientIP} >> ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`)
			: logger.error(`Error    ${event.clientIP} >> ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`);
		return { success: false, code: 'FAILED' };
	}
};

const knownStatuses = new Set(['TOO_MANY_REQUESTS', 'REPORTED', 'READY_FOR_BULK_REPORT', 'RL_BULK_REPORT']);
const isIPReportedRecently = (event, reportedIPs) => {
	const now = Date.now();
	return reportedIPs.some(entry =>
		(entry.ip === event.clientIP || entry.rayId === event.rayName) &&
		knownStatuses.has(entry.status) &&
		(now - entry.timestamp) < MAIN.IP_REPORT_COOLDOWN
	) ? { recentlyReported: true } : { recentlyReported: false };
};

const processData = async () => {
	logger.info(`====================== STARTING REPORTING CYCLE #${cycleId} ======================`);

	// IP refresh
	await refreshServerIPs();
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return logger.error(`getServerIPs() returned an invalid result: ${ips}`);

	// Cache
	const [whitelist, reportedIPs] = await Promise.all([
		getFilters(),
		readReportedIPs(),
	]);

	// Fetch events
	const reportedIPsSet = new Set(reportedIPs.map(e => e.ip));
	const events = await fetchCloudflareEvents(whitelist);
	if (!events?.length) {
		return logger.info('No events fetched from Cloudflare. Skipping this cycle.');
	}

	// Report IPs
	let cycleErrorCounts = 0, cycleProcessedCount = 0, cycleReportedCount = 0, cycleSkippedCount = 0;
	for (const event of events) {
		cycleProcessedCount++;

		const { clientIP, clientRequestPath } = event;
		if (
			ips.includes(clientIP) ||
			whitelist.endpoints.includes(clientRequestPath) ||
			clientRequestPath.length > MAIN.MAX_URL_LENGTH ||
			reportedIPsSet.has(clientIP) ||
			isIPReportedRecently(event, reportedIPs).recentlyReported
		) {
			cycleSkippedCount++;
			continue;
		}

		const categories = event.source === 'l7ddos' ? '4,19' : '19';
		const result = await reportIP(event, categories, GENERATE_COMMENT(event));

		await logToCSV(event, result.code);

		if (['REPORTED', 'RL_BULK_REPORT', 'READY_FOR_BULK_REPORT'].includes(result.code)) {
			reportedIPsSet.add(clientIP);
		}

		if (result.success) {
			cycleReportedCount++;
			await new Promise(res => setTimeout(res, MAIN.SUCCESS_COOLDOWN));
			continue;
		}

		if (result.code === 'FAILED' || !['ALREADY_IN_BUFFER', 'READY_FOR_BULK_REPORT', 'RL_BULK_REPORT'].includes(result.code)) cycleErrorCounts++;
	}

	logger.info(`Summary » Processed: ${cycleProcessedCount}; Reported: ${cycleReportedCount}; Skipped: ${cycleSkippedCount}; Errors: ${cycleErrorCounts}`);
	logger.info(`====================== REPORTING CYCLE #${cycleId} COMPLETED ======================`);
	cycleId++;
};

(async () => {
	banner();

	// Auto updates
	if (MAIN.AUTO_UPDATE_ENABLED && MAIN.AUTO_UPDATE_SCHEDULE && MAIN.SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js')();
	} else {
		await require('./scripts/services/version.js');
	}

	// Fetch IPs
	await refreshServerIPs();

	// Bulk Report
	await loadBufferFromFile();
	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		logger.info(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	// Sefinek API
	if (MAIN.SEFIN_API_REPORTING && MAIN.SEFIN_API_SECRET_TOKEN && MAIN.SEFIN_API_REPORT_SCHEDULE) {
		new CronJob(MAIN.SEFIN_API_REPORT_SCHEDULE, SefinekAPI, null, true);
	}

	const runSefinekAPI = process.argv.includes('--report-to-sapi');
	if (runSefinekAPI) await SefinekAPI();

	// Report Schedule
	new CronJob(MAIN.REPORT_SCHEDULE, processData, null, true);

	// Ready
	await logger.webhook(`[${repoSlug}](${repoUrl}) was successfully started!`, 0x59D267);
	logger.success(`All set! ${MAIN.RUN_ON_START ? 'Starting first cycle shortly' : 'Waiting for the first scheduled cycle'}...`);
	process.send?.('ready');

	// Run on start?
	if (MAIN.RUN_ON_START || process.argv.includes('--run-on-start')) await processData();
})();

const gracefulShutdown = async signal => {
	logger.info(`Received ${signal}, flushing pending writes...`);
	try {
		await saveBufferToFile();
	} catch (err) {
		logger.error(`Error during shutdown flush: ${err.message}`);
	}
	process.exit(0);
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));