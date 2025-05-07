const { CronJob } = require('cron');
const axios = require('./scripts/services/axios.js');
const { MAIN, GENERATE_COMMENT } = require('./config.js');
const PAYLOAD = require('./utils/services/payload.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const SefinekAPI = require('./utils/services/SefinekAPI.js');
const headers = require('./utils/headers.js');
const { logToCSV, readReportedIPs } = require('./utils/services/csv.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const getFilters = require('./utils/services/getFilters.js');
const log = require('./scripts/log.js');

const ABUSE_STATE = { isLimited: false, isBuffering: false, sentBulk: false };
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
			log(`Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`, 1);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			log(`Rate limit is still active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`, 1);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const fetchCloudflareEvents = async whitelist => {
	try {
		const { data, status } = await axios.post('https://api.cloudflare.com/client/v4/graphql', PAYLOAD(1000), {
			headers: headers.CLOUDFLARE,
		});

		const events = data?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive;
		if (!events) throw new Error(`Failed to retrieve data from Cloudflare (status ${status}): ${JSON.stringify(data?.errors)}`);

		const isWhitelisted = event =>
			getServerIPs().includes(event.ip) ||
			whitelist.userAgents.some(ua => event.userAgent.includes(ua)) ||
			whitelist.imgExtensions.some(ext => event.clientRequestPath.endsWith(ext)) ||
			whitelist.domains.some(domain => event.clientRequestHTTPHost?.includes(domain)) ||
			whitelist.endpoints.some(endpoint => event.clientRequestPath?.includes(endpoint));

		const filtered = events.filter(event => !isWhitelisted(event));

		log(`Fetched ${events.length} events (filtered ${filtered.length}) from Cloudflare`, 1);
		return filtered;
	} catch (err) {
		log(err.response?.data
			? `${err.response.status} HTTP ERROR Cloudflare API: ${JSON.stringify(err.response.data, null, 2)}`
			: `Unknown error with Cloudflare API: ${err.message}`, 3
		);
		return [];
	}
};

const reportIP = async (event, categories, comment) => {
	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (!BULK_REPORT_BUFFER.has(event.clientIP)) {
			BULK_REPORT_BUFFER.set(event.clientIP, { categories, timestamp: event.datetime, comment });
			await saveBufferToFile();
			log(`Queued ${event.clientIP} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`, 1);
			return { success: false, code: 'READY_FOR_BULK_REPORT' };
		}
		return { success: false, code: 'ALREADY_IN_BUFFER' };
	}

	try {
		await axios.post('https://api.abuseipdb.com/api/v2/report', {
			ip: event.clientIP,
			categories,
			comment,
		}, { headers: headers.ABUSEIPDB });

		log(`Reported ${event.clientIP}; URI: ${event.clientRequestPath}`, 1);
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
				log(`Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toISOString()}`, 0, true);
			}

			if (!BULK_REPORT_BUFFER.has(event.clientIP)) {
				BULK_REPORT_BUFFER.set(event.clientIP, { timestamp: event.datetime, categories, comment });
				await saveBufferToFile();
				log(`Queued ${event.clientIP} for bulk report due to rate limit`);
				return { success: false, code: 'RL_BULK_REPORT' };
			}

			return { success: false, code: 'ALREADY_IN_BUFFER' };
		}

		log(`Failed to report ${event.clientIP}; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`, 3);
		return { success: false, code: 'FAILED' };
	}
};

const knownStatuses = new Set(['TOO_MANY_REQUESTS', 'REPORTED', 'READY_FOR_BULK_REPORT', 'RL_BULK_REPORT']);
const isIPReportedRecently = (event, reportedIPs) => {
	const now = Date.now();
	for (const entry of reportedIPs) {
		if (
			(entry.ip === event.clientIP || entry.rayId === event.rayName) &&
			knownStatuses.has(entry.status) &&
			(now - entry.timestamp) < MAIN.REPORTED_IP_COOLDOWN
		) {
			return { recentlyReported: true, reason: entry.status };
		}
	}

	return { recentlyReported: false };
};

const processData = async () => {
	log(`======================== Reporting Cycle No. ${cycleId} ========================`);

	const whitelist = await getFilters();
	const events = await fetchCloudflareEvents(whitelist);
	if (!events || events.length === 0) {
		log('No events fetched, skipping cycle...');
		return;
	}

	await refreshServerIPs();
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return log(`Invalid IPs array from getServerIPs(): ${ips}`, 3);

	log(`Fetched ${ips.length} of your IP addresses`, 1);

	let cycleErrorCounts = 0, cycleProcessedCount = 0, cycleReportedCount = 0, cycleSkippedCount = 0;

	try {
		const reportedIPs = await readReportedIPs();
		const sessionReportedIPs = new Set(reportedIPs.map(e => e.ip));

		for (const event of events) {
			cycleProcessedCount++;

			if (
				ips.includes(event.clientIP) ||
				whitelist.endpoints.includes(event.clientRequestPath) ||
				event.clientRequestPath.length > MAIN.MAX_URL_LENGTH
			) {
				cycleSkippedCount++;
				continue;
			}

			if (sessionReportedIPs.has(event.clientIP)) {
				cycleSkippedCount++;
				continue;
			}

			const { recentlyReported } = isIPReportedRecently(event, reportedIPs);
			if (recentlyReported) {
				cycleSkippedCount++;
				continue;
			}

			const result = await reportIP(event, '14', GENERATE_COMMENT(event));
			await logToCSV(event, result.code);

			if (['REPORTED', 'RL_BULK_REPORT', 'READY_FOR_BULK_REPORT'].includes(result.code)) {
				sessionReportedIPs.add(event.clientIP);
			}

			if (result.success) {
				cycleReportedCount++;
				await new Promise(resolve => setTimeout(resolve, MAIN.SUCCESS_COOLDOWN));
			} else {
				switch (result.code) {
				case 'FAILED':
					cycleErrorCounts++;
					break;
				case 'ALREADY_IN_BUFFER':
				case 'READY_FOR_BULK_REPORT':
				case 'RL_BULK_REPORT':
					break;
				default:
					cycleErrorCounts++;
					break;
				}
			}

		}
	} catch (err) {
		log(err.stack, 3, true);
	}

	log(`- Reported IPs: ${cycleReportedCount}`);
	log(`- Total IPs processed: ${cycleProcessedCount}`);
	log(`- Skipped IPs: ${cycleSkippedCount}`);
	log(`- Errors: ${cycleErrorCounts}`);
	log('===================== End of Reporting Cycle =====================');

	cycleId++;
};

(async () => {
	log('Loading data, please wait...');

	// Bulk
	await loadBufferFromFile();
	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		log(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	// Sefinek API
	if (MAIN.SEFIN_API_REPORTING && MAIN.SEFIN_API_SECRET_TOKEN && MAIN.SEFIN_API_REPORT_SCHEDULE) {
		new CronJob(MAIN.SEFIN_API_REPORT_SCHEDULE, SefinekAPI, null, true);
	}

	// AbuseIPDB
	new CronJob(MAIN.REPORT_SCHEDULE, processData, null, true);

	// Ready
	process.send?.('ready');

	// Run on start?
	if (MAIN.RUN_ON_START) await processData();
})();