require('dotenv').config();

const { axios } = require('./services/axios.js');
const { CYCLE_INTERVAL, REPORTED_IP_COOLDOWN, MAX_URL_LENGTH, SUCCESS_COOLDOWN, SEFINEK_API_INTERVAL, REPORT_TO_SEFINEK_API } = require('./scripts/config.js');
const PAYLOAD = require('./services/payload.js');
const generateComment = require('./scripts/generateComment.js');
const SefinekAPI = require('./services/SefinekAPI.js');
const isImageRequest = require('./scripts/isImageRequest.js');
const headers = require('./scripts/headers.js');
const { logToCSV, readReportedIPs, wasImageRequestLogged } = require('./services/csv.js');
const formatDelay = require('./scripts/formatDelay.js');
const clientIp = require('./services/clientIp.js');
const whitelist = require('./scripts/whitelist.js');
const log = require('./scripts/log.js');

const fetchBlockedIPs = async () => {
	try {
		const { data, status } = await axios.post('https://api.cloudflare.com/client/v4/graphql', PAYLOAD(), { headers: headers.CLOUDFLARE });
		const events = data?.data?.viewer?.zones[0]?.firewallEventsAdaptive;
		if (events) {
			const filtered = events.filter(x =>
				x.ip !== clientIp.getAddress() &&
				(
					x.source === 'securitylevel' ||
					x.source === 'badscore' ||
					(
						!whitelist.domains.some(subdomain => x.clientRequestHTTPHost?.includes(subdomain)) &&
						!whitelist.userAgents.some(ua => x.userAgent?.includes(ua)) &&
						!whitelist.endpoints.some(endpoint => x.clientRequestPath?.includes(endpoint))
					)
				)
			);

			log(0, `Fetched ${events.length} (filtered ${filtered.length}) events from Cloudflare`);
			return filtered;
		} else {
			throw new Error(`Failed to retrieve data from Cloudflare (status ${status}); ${JSON.stringify(data?.errors)}`);
		}
	} catch (err) {
		log(2, err.response?.data ? `${err.response.status} HTTP ERROR Cloudflare API: ${JSON.stringify(err.response.data, null, 2)}` : `Unknown error with Cloudflare API: ${err.message}`);
		return null;
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

	if (lastReport && (Date.now() - lastReport.timestamp) < REPORTED_IP_COOLDOWN) {
		return { recentlyReported: true, timeDifference: Date.now() - lastReport.timestamp, reason: lastReport.status === 'TOO_MANY_REQUESTS' ? 'RATE-LIMITED' : 'REPORTED' };
	}

	return { recentlyReported: false };
};

const reportIP = async (event, uri, country, hostname, endpoint, cycleErrorCounts) => {
	if (!uri) {
		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'MISSING_URI');
		log(1, `Missing URL ${event.clientIP}; URI: ${uri}`);
		return false;
	}

	if (event.clientIP === clientIp.address) {
		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'YOUR_IP_ADDRESS');
		log(0, `Your IP address (${event.clientIP}) was unexpectedly received from Cloudflare. URI: ${uri}`);
		return false;
	}

	if (uri.length > MAX_URL_LENGTH) {
		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'URI_TOO_LONG');
		// log(0, `URI too long ${event.clientIP}; Received: ${uri}`);
		return false;
	}

	try {
		await axios.post('https://api.abuseipdb.com/api/v2/report', {
			ip: event.clientIP,
			categories: '19',
			comment: generateComment(event),
		}, { headers: headers.ABUSEIPDB });

		logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'REPORTED');
		log(0, `Reported ${event.clientIP}; URI: ${uri}`);

		return true;
	} catch (err) {
		if (err.response?.status === 429) {
			logToCSV(event.rayName, event.clientIP, country, hostname, endpoint, event.userAgent, event.action, 'TOO_MANY_REQUESTS');
			log(0, `429 for ${event.clientIP} (${event.rayName}); Endpoint: ${endpoint}`);
			cycleErrorCounts.blocked++;
		} else {
			log(2, `Error ${err.response?.status} while reporting ${event.clientIP}; URI: ${uri}; (${err.response?.data})`);
			cycleErrorCounts.otherErrors++;
		}

		return false;
	}
};

(async () => {
	log(0, 'Loading data, please wait...');
	await clientIp.fetchIPAddress();

	// Sefinek API
	if (REPORT_TO_SEFINEK_API && SEFINEK_API_INTERVAL && process.env.SEFINEK_API_SECRET) {
		setInterval(SefinekAPI, SEFINEK_API_INTERVAL);
	}

	// Ready
	if (process.env.NODE_ENV === 'production') {
		try {
			process.send('ready');
		} catch (err) {
			log(0, `Failed to send ready signal to parent process. ${err.message}`);
		}
	}

	// AbuseIPDB
	let cycleId = 1;
	while (true) {
		log(0, `===================== Reporting Cycle No. ${cycleId} =====================`);

		const blockedIPEvents = await fetchBlockedIPs();
		if (!blockedIPEvents) {
			log(1, 'No events fetched, skipping cycle...');
			continue;
		}

		const userIp = clientIp.getAddress();
		if (!userIp) log(1, `Your IP address is missing! Received: ${userIp}`);

		let cycleImageSkippedCount = 0, cycleProcessedCount = 0, cycleReportedCount = 0, cycleSkippedCount = 0;
		const cycleErrorCounts = { blocked: 0, otherErrors: 0 };
		let imageRequestLogged = false;

		for (const event of blockedIPEvents) {
			cycleProcessedCount++;
			const ip = event.clientIP;
			if (ip === userIp) {
				log(0, `The IP address ${ip} belongs to this machine. Ignoring...`);
				cycleSkippedCount++;
				continue;
			}

			if (whitelist.endpoints.includes(event.clientRequestPath)) return log(0, `Skipping ${event.clientRequestPath}...`);

			const reportedIPs = readReportedIPs();
			const { recentlyReported } = isIPReportedRecently(event.rayName, ip, reportedIPs);
			if (recentlyReported) {
				// if (process.env.NODE_ENV === 'development') {
				// 	const hoursAgo = Math.floor(timeDifference / (1000 * 60 * 60));
				// 	const minutesAgo = Math.floor((timeDifference % (1000 * 60 * 60)) / (1000 * 60));
				// 	const secondsAgo = Math.floor((timeDifference % (1000 * 60)) / 1000);
				// 	log(0, `${ip} was ${reason} ${hoursAgo}h ${minutesAgo}m ${secondsAgo}s ago. Skipping...`);
				// }

				cycleSkippedCount++;
				continue;
			}

			if (isImageRequest(event.clientRequestPath)) {
				cycleImageSkippedCount++;
				if (!wasImageRequestLogged(ip, reportedIPs)) {
					if (imageRequestLogged) continue;
					log(0, 'Skipping image requests in this cycle...');
					imageRequestLogged = true;
				}

				continue;
			}

			const wasReported = await reportIP(event, `${event.clientRequestHTTPHost}${event.clientRequestPath}`, event.clientCountryName, event.clientRequestHTTPHost, event.clientRequestPath, cycleErrorCounts);
			if (wasReported) {
				cycleReportedCount++;
				await new Promise(resolve => setTimeout(resolve, SUCCESS_COOLDOWN));
			}
		}

		log(0, `- Reported IPs: ${cycleReportedCount}`);
		log(0, `- Total IPs processed: ${cycleProcessedCount}`);
		log(0, `- Skipped IPs: ${cycleSkippedCount}`);
		log(0, `- Ignored image requests: ${cycleImageSkippedCount}`);
		log(0, `- Rate-limits: ${cycleErrorCounts.blocked}`);
		log(0, `- Other errors: ${cycleErrorCounts.otherErrors}`);
		log(0, '===================== End of Reporting Cycle =====================');

		log(0, `Waiting ${formatDelay(CYCLE_INTERVAL)}...`);
		cycleId++;
		await new Promise(resolve => setTimeout(resolve, CYCLE_INTERVAL));
	}
})();