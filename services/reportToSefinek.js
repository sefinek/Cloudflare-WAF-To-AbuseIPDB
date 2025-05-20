const FormData = require('form-data');
const { SEFINEK_API } = require('../scripts/headers.js');
const { axios } = require('../scripts/services/axios.js');
const { readReportedIPs, updateSefinekAPIInCSV } = require('./csv.js');
const { getServerIPs } = require('../scripts/services/ipFetcher.js');
const logger = require('../scripts/logger.js');

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
		const payload = uniqueLogs.map(ip => ({
			rayId: ip.rayId,
			ip: ip.ip,
			endpoint: ip.endpoint,
			userAgent: ip.userAgent,
			action: ip.action,
			country: ip.country,
			timestamp: ip.timestamp,
		}));

		const form = new FormData();
		form.append('file', Buffer.from(JSON.stringify(payload, null, 2)), {
			filename: 'reports.json',
			contentType: 'application/json',
		});

		const res = await axios.post('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb', form, {
			headers: { ...form.getHeaders(), ...SEFINEK_API },
		});

		if (res.data.success) {
			logger.log(`Sefinek API (status: ${res.status}): Successfully sent ${uniqueLogs.length} logs`, 1);
		} else {
			logger.log(`Sefinek API (status: ${res.status}): ${res.data.message || 'Something went wrong'}`, 2);
		}

		await Promise.all(uniqueLogs.map(ip => updateSefinekAPIInCSV(ip.rayId, true)));
	} catch (err) {
		if (err.response?.data?.message?.includes('No valid or unique')) return;
		const rawMsg = err.response?.data?.message;
		const msg = Array.isArray(rawMsg) ? rawMsg[0] : (typeof rawMsg === 'object' ? JSON.stringify(rawMsg) : rawMsg || err.message);
		logger.log(`Sefinek API (status: ${err.response?.status ?? 'unknown'}): Failed to send logs! Message: ${typeof msg === 'object' ? JSON.stringify(msg) : msg}`, 3);
	}
};