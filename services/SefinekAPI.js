const axios = require('./axios.js');
const { readReportedIPs, updateSefinekAPIInCSV } = require('./csv.js');
const log = require('../utils/log.js');
const fetchServerIP = require('./fetchServerIP.js');
const whitelist = require('../utils/whitelist.js');
const { MAIN } = require('../config.js').CONFIG;

module.exports = async () => {
	const reportedIPs = (readReportedIPs() || []).filter(x =>
		x.status === 'REPORTED' &&
		x.ip !== fetchServerIP() &&
		!x.sefinekAPI &&
		(
			x.source === 'securitylevel' ||
			x.source === 'badscore' ||
			(
				!(/crawler|spider|bot/gi).test(x.userAgent) &&
				!whitelist.domains.some(subdomain => x.clientRequestHTTPHost?.includes(subdomain)) &&
				!whitelist.userAgents.some(ua => x.userAgent?.includes(ua)) &&
				!whitelist.endpoints.some(endpoint => x.clientRequestPath?.includes(endpoint))
			)
		)
	);

	if (!reportedIPs.length) return;

	const seenIPs = new Set();
	const uniqueLogs = reportedIPs.filter(ip => {
		if (seenIPs.has(ip.ip)) return false;
		seenIPs.add(ip.ip);
		return true;
	});

	if (!uniqueLogs.length) return log(0, 'No unique IPs to send to Sefinek API');

	try {
		const res = await axios.post('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb/post', {
			reportedIPs: uniqueLogs.map(ip => ({
				rayId: ip.rayId,
				ip: ip.ip,
				endpoint: ip.endpoint,
				userAgent: ip.userAgent,
				action: ip.action,
				country: ip.country,
				timestamp: ip.timestamp,
			})),
		}, { headers: { 'Authorization': MAIN.SECRET_TOKEN } });

		log(0, `Successfully sent ${uniqueLogs.length} logs to Sefinek API. Status: ${res.status}`);

		uniqueLogs.forEach(ip => updateSefinekAPIInCSV(ip.rayId, true));
	} catch (err) {
		log(2, `Failed to send logs to Sefinek API. Status: ${err.response?.status}. Message: ${err.response?.data?.message || err.stack}`);
	}
};