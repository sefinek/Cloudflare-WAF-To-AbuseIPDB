const fs = require('node:fs');
const path = require('node:path');
const PAYLOAD = require('./generateFirewallQuery.js');
const { axios } = require('../scripts/services/axios.js');
const headers = require('../scripts/headers.js');
const logger = require('../scripts/logger.js');
const { MAIN } = require('../config.js');

const ensureFile = filePath => {
	if (fs.existsSync(filePath)) return;
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, '');
};

const fetchCloudflareEvents = async () => {
	const rawZoneIds = MAIN.CLOUDFLARE_ZONE_IDS || MAIN.CLOUDFLARE_ZONE_ID;
	const zoneIds = Array.isArray(rawZoneIds) ? rawZoneIds : [rawZoneIds];
	const allEvents = [];

	for (const zoneId of zoneIds) {
		try {
			const { data, status } = await axios.post('https://api.cloudflare.com/client/v4/graphql', PAYLOAD(10000, zoneId), headers.CLOUDFLARE);

			const events = data?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive;
			if (!events) throw new Error(`Failed to retrieve data from Cloudflare (status ${status}): ${JSON.stringify(data?.errors)}`);

			const l7ddosEvents = events.filter(e => e.source === 'l7ddos');
			logger.log(`Zone ${zoneId}: ${events.length} events fetched (${l7ddosEvents.length} L7 DDoS)`, 1);
			allEvents.push(...l7ddosEvents);
		} catch (err) {
			logger.log(err.response?.data ? `${err.response.status} HTTP ERROR for zone ${zoneId}: ${JSON.stringify(err.response.data, null, 2)}` : `Unknown error for zone ${zoneId}: ${err.message}`, 3);
		}
	}

	return allEvents;
};

const saveToCSV = (events, filePath = 'report.csv') => {
	const map = new Map();
	for (const { clientIP, datetime } of events) {
		if (!map.has(clientIP)) map.set(clientIP, `${clientIP},4,${new Date(datetime).toISOString()},Detected L7 DDoS via Cloudflare`);
	}

	ensureFile(filePath);
	if (!fs.statSync(filePath).size) fs.appendFileSync(filePath, 'IP,Categories,ReportDate,Comment\n');

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
		logger.log(`Saved ${events.length} L7 DDoS events to CSV and TXT`, 1);
	} else {
		logger.log('No L7 DDoS events found');
	}
})();