const { CronJob } = require('cron');
const axios = require('./scripts/services/axios.js');
const { CONFIG, GENERATE_COMMENT } = require('./config.js');
const PAYLOAD = require('./utils/services/payload.js');
const SefinekAPI = require('./utils/services/SefinekAPI.js');
const headers = require('./utils/headers.js');
const { logToCSV, readReportedIPs } = require('./utils/services/csv.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const getFilters = require('./utils/services/getFilters.js');
const log = require('./scripts/log.js');

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

const isIPReportedRecently = (rayId, ip, reportedIPs) => {
	const lastReport = reportedIPs.reduce((latest, entry) => {
		if (
			(entry.rayId === rayId || entry.ip === ip) &&
			(entry.status === 'TOO_MANY_REQUESTS' || entry.status === 'REPORTED') &&
			(!latest || entry.timestamp > latest.timestamp)
		) return entry;
		return latest;
	}, null);

	if (lastReport && (Date.now() - lastReport.timestamp) < CONFIG.CYCLES.REPORTED_IP_COOLDOWN) {
		return { recentlyReported: true, timeDifference: Date.now() - lastReport.timestamp, reason: lastReport.status === 'TOO_MANY_REQUESTS' ? 'RATE-LIMITED' : 'REPORTED' };
	}

	return { recentlyReported: false };
};

const reportIP = async (event, uri, country, hostname, endpoint, cycleErrorCounts) => {
	if (!uri) {
		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'MISSING_URI');
		log(`Missing URL ${event.clientIP}; URI: ${uri}`, 2);
		return false;
	}

	if (getServerIPs().includes(event.clientIP)) {
		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'YOUR_IP_ADDRESS');
		log(`Your IP address (${event.clientIP}) was unexpectedly received from Cloudflare. URI: ${uri}`);
		return false;
	}

	if (uri.length > CONFIG.CYCLES.MAX_URL_LENGTH) {
		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'URI_TOO_LONG');
		// log(`URI too long ${event.clientIP}; Received: ${uri}`);
		return false;
	}

	try {
		await axios.post('https://api.abuseipdb.com/api/v2/report', {
			ip: event.clientIP,
			categories: '19',
			comment: GENERATE_COMMENT(event),
		}, { headers: headers.ABUSEIPDB });

		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'REPORTED');
		log(`Reported ${event.clientIP}; URI: ${uri}`, 1);

		return true;
	} catch (err) {
		if (err.response?.status === 429) {
			logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'TOO_MANY_REQUESTS');
			log(`429 for ${event.clientIP} (${event.rayName}); Endpoint: ${endpoint}`);
			cycleErrorCounts.blocked++;
		} else {
			const errorDetails = Array.isArray(err.response?.data?.errors) && err.response.data.errors.length > 0
				? err.response.data.errors[0]?.detail
				: JSON.stringify(err.response?.data) || err.message || 'Unknown error';
			log(`Error ${err.response?.status} while reporting ${event?.clientIP}; URI: ${uri}; ${errorDetails}`, 3);

			cycleErrorCounts.otherErrors++;
		}

		return false;
	}
};

let cycleId = 1;

const cron = async () => {
	log(`======================== Reporting Cycle No. ${cycleId} ========================`);

	// Fetch cloudflare events
	const whitelist = await getFilters();
	const events = await fetchCloudflareEvents(whitelist);
	if (!events) return log('No events fetched, skipping cycle...');

	// IP
	await refreshServerIPs();
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return log('For some reason, \'ips\' is not an array', 3);
	log(`Fetched ${getServerIPs()?.length} of your IP addresses`, 1);

	// Cycle
	let cycleProcessedCount = 0, cycleReportedCount = 0, cycleSkippedCount = 0;
	const cycleErrorCounts = { blocked: 0, otherErrors: 0 };

	for (const event of events) {
		cycleProcessedCount++;
		const ip = event.clientIP;
		if (getServerIPs().includes(ip)) {
			log(`The IP address ${ip} belongs to this machine. Ignoring...`);
			cycleSkippedCount++;
			continue;
		}

		if (whitelist.endpoints.includes(event.clientRequestPath)) {
			log(`Skipping ${event.clientRequestPath}...`);
			continue;
		}

		const reportedIPs = readReportedIPs();
		const { recentlyReported } = isIPReportedRecently(event.rayName, ip, reportedIPs);
		if (recentlyReported) {
			cycleSkippedCount++;
			continue;
		}

		const wasReported = await reportIP(event, `${event.clientRequestHTTPHost}${event.clientRequestPath}`, event.clientCountryName, event.clientRequestHTTPHost, event.clientRequestPath, cycleErrorCounts);
		if (wasReported) {
			cycleReportedCount++;
			await new Promise(resolve => setTimeout(resolve, CONFIG.CYCLES.SUCCESS_COOLDOWN));
		}
	}

	log(`- Reported IPs: ${cycleReportedCount}`);
	log(`- Total IPs processed: ${cycleProcessedCount}`);
	log(`- Skipped IPs: ${cycleSkippedCount}`);
	log(`- Rate-limits: ${cycleErrorCounts.blocked}`);
	log(`- Other errors: ${cycleErrorCounts.otherErrors}`);
	log('===================== End of Reporting Cycle =====================');

	cycleId++;
	await new Promise(resolve => setTimeout(resolve));
};

(async () => {
	log('Loading data, please wait...');

	// Sefinek API
	if (CONFIG.SEFINEK_API.ENABLED && CONFIG.SEFINEK_API.SECRET_TOKEN && CONFIG.SEFINEK_API.REPORT_SCHEDULE) {
		new CronJob(CONFIG.SEFINEK_API.REPORT_SCHEDULE, SefinekAPI, null, true);
	}

	// AbuseIPDB
	new CronJob(CONFIG.CYCLES.REPORT_SCHEDULE, cron, null, true);

	// Ready
	process.send && process.send('ready');

	// Run on start?
	if (CONFIG.MAIN.RUN_ON_START) await cron();
})();