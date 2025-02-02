const axios = require('./axios.js');
const { readReportedIPs, updateSefinekAPIInCSV } = require('./csv.js');
const log = require('../utils/log.js');
const fetchServerIP = require('./fetchServerIP.js');
const { SEFINEK_API } = require('../config.js').CONFIG;

module.exports = async () => {
	const reportedIPs = (readReportedIPs() || []).filter(x => x.status === 'REPORTED' && x.ip !== fetchServerIP() && !x.sefinekAPI);
	if (!reportedIPs.length) return;

	const seenIPs = new Set();
	const uniqueLogs = reportedIPs.filter(ip => {
		if (seenIPs.has(ip.ip)) return false;
		seenIPs.add(ip.ip);
		return true;
	});

	if (!uniqueLogs.length) return log(0, 'No unique IPs to send to Sefinek API');

	try {
		// http://127.0.0.1:4010/api/v2/cloudflare-waf-abuseipdb
		const res = await axios.post('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb', {
			reportedIPs: uniqueLogs.map(ip => ({
				rayId: ip.rayId,
				ip: ip.ip,
				endpoint: ip.endpoint,
				userAgent: ip.userAgent,
				action: ip.action,
				country: ip.country,
				timestamp: ip.timestamp,
			})),
		}, { headers: { 'Authorization': SEFINEK_API.SECRET_TOKEN } });

		log(0, `Successfully sent ${uniqueLogs.length} logs to Sefinek API! Status: ${res.status}`);

		uniqueLogs.forEach(ip => updateSefinekAPIInCSV(ip.rayId, true));
	} catch (err) {
		const msg = err?.response?.data?.message;
		const errMsg = Array.isArray(msg) ? msg[0] : msg || err.message;
		if (!errMsg?.includes('No valid or unique')) {
			log(2, `Failed to send logs to Sefinek API! Status: ${err?.response?.status ?? 'Unknown'}; Message: ${errMsg}`);
		}
	}
};