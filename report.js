const fs = require('node:fs');
const PAYLOAD = require('./services/payload.js');
const axios = require('./services/axios.js');
const headers = require('./utils/headers.js');
const log = require('./utils/log.js');

const fetchCloudflareEvents = async () => {
	try {
		const { data, status } = await axios.post('https://api.cloudflare.com/client/v4/graphql', PAYLOAD(), {
			headers: headers.CLOUDFLARE,
		});

		const events = data?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive;
		if (!events) throw new Error(`Failed to retrieve data from Cloudflare (status ${status}): ${JSON.stringify(data?.errors)}`);

		const filtered = events.filter(event => event.source === 'l7ddos');
		log(0, `Fetched ${events.length} events (filtered ${filtered.length} L7 DDoS)`);
		return filtered;
	} catch (err) {
		log(2, `Unknown error with Cloudflare API: ${err.message}`);
		return [];
	}
};

const saveToCSV = (events, path = 'report.csv') => {
	const uniqueMap = new Map();

	for (const event of events) {
		if (!uniqueMap.has(event.clientIP)) {
			uniqueMap.set(event.clientIP, {
				ip: event.clientIP,
				date: new Date(event.datetime).toISOString(),
			});
		}
	}

	if (!fs.existsSync(path)) fs.writeFileSync(path, 'IP,Categories,ReportDate,Comment\n');
	const rows = [...uniqueMap.values()].map(({ ip, date }) => `${ip},4,${date},Detected L7 DDoS via Cloudflare`);
	fs.appendFileSync(path, rows.join('\n') + '\n');
};

const saveToTXT = (events, path = 'report.txt') => {
	const uniqueIPs = [...new Set(events.map(event => event.clientIP))];
	fs.appendFileSync(path, uniqueIPs.join('\n') + '\n');
};

(async () => {
	const events = await fetchCloudflareEvents();

	if (events.length > 0) {
		saveToCSV(events);
		saveToTXT(events);
	}
})();
