const fs = require('node:fs');
const path = require('node:path');
const PAYLOAD = require('./generateFirewallQuery.js');
const { axios } = require('../scripts/services/axios.js');
const headers = require('../scripts/headers.js');
const logger = require('../scripts/logger.js');

const fetchCloudflareEvents = async () => {
	try {
		const { data } = await axios.post('https://api.cloudflare.com/client/v4/graphql', PAYLOAD(10000), { headers: headers.CLOUDFLARE });

		const events = data?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive || [];
		const filtered = events.filter(e => e.source === 'l7ddos');

		logger.log(`Fetched ${events.length} events from Cloudflare (filtered ${filtered.length} L7 DDoS)`, 1);
		return filtered;
	} catch (err) {
		logger.log(`Cloudflare API error: ${err.message}`, 3);
		return [];
	}
};

const ensureFile = filePath => {
	if (fs.existsSync(filePath)) return;
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, '');
};

const saveToCSV = (events, filePath = 'report.csv') => {
	const map = new Map();
	for (const { clientIP, datetime } of events) {
		if (!map.has(clientIP)) {
			map.set(clientIP, `${clientIP},4,${new Date(datetime).toISOString()},Detected L7 DDoS via Cloudflare`);
		}
	}

	ensureFile(filePath);
	if (fs.statSync(filePath).size === 0) {
		fs.appendFileSync(filePath, 'IP,Categories,ReportDate,Comment\n');
	}

	fs.appendFileSync(filePath, [...map.values()].join('\n') + '\n');
};

const saveToTXT = (events, filePath = 'report.txt') => {
	const uniqueIPs = new Set(events.map(e => e.clientIP));
	ensureFile(filePath);
	fs.appendFileSync(filePath, [...uniqueIPs].join('\n') + '\n');
};

(async () => {
	const events = await fetchCloudflareEvents();
	if (events.length) {
		saveToCSV(events);
		saveToTXT(events);
	}
})();