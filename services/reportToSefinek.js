const { axios } = require('../scripts/services/axios.js');
const { readReportedIPs, updateSefinekAPIInCSV } = require('./csv.js');
const { getServerIPs } = require('../scripts/services/ipFetcher.js');
const logger = require('../scripts/logger.js');
const { SEFIN_API_SECRET_TOKEN } = require('../config.js').MAIN;

module.exports = async () => {
	const reportedIPs = (await readReportedIPs() || []).filter(x => x.status === 'REPORTED' && !getServerIPs().includes(x.ip) && !x.sefinekAPI);
	if (!reportedIPs.length) return logger.log('Sefinek API: No data to report');

	const seenIPs = new Set();
	const uniqueLogs = reportedIPs.filter(ip => {
		if (seenIPs.has(ip.ip)) return false;
		seenIPs.add(ip.ip);
		return true;
	});

	if (!uniqueLogs.length) return logger.log('Sefinek API: No unique IPs to send');

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
		}, { headers: { 'X-API-Key': SEFIN_API_SECRET_TOKEN } });

		logger.log(`Sefinek API: Successfully sent ${uniqueLogs.length} logs! Status: ${res.status}`, 1);

		for (const ip of uniqueLogs) {
			await updateSefinekAPIInCSV(ip.rayId, true);
		}
	} catch (err) {
		if (!err.response?.data?.message?.includes('No valid or unique')) {
			const msg = err.response?.data?.message[0] || err.response?.data?.message || err.message;
			logger.log(`Sefinek API: Failed to send logs! Status: ${err.response?.status ?? 'Unknown'}; Message: ${typeof msg === 'object' ? JSON.stringify(msg) : msg}`, 3);
		}
	}
};