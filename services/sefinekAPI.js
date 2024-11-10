const { axios } = require('./axios.js');
const { readReportedIPs, updateSefinekAPIInCSV } = require('./csv.js');
const log = require('../scripts/log.js');
const clientIp = require('./clientIp.js');
const whitelist = require('../scripts/whitelist.js');

const API_URL = `${process.env.SEFINEK_API_URL}/cloudflare-waf-abuseipdb/post`;

module.exports = async () => {
	const reportedIPs = readReportedIPs().filter(x =>
		x.status === 'REPORTED' &&
		x.ip !== clientIp.getAddress() &&
		x.hostname !== 'blocklist.sefinek.net' && // Domain
		!whitelist.subdomains.some(subdomain => x.clientRequestHTTPHost.includes(subdomain)) && // Subdomains
		!whitelist.useragents.some(ua => x.userAgent.includes(ua)) && // User-agents
		!whitelist.endpoints.some(endpoint => x.clientRequestPath.includes(endpoint)) && // Endpoints
		!(/crawler|spider|bot/gi).test(x.useragent) && // Bots
		!x.sefinekAPI
	);
	if (!reportedIPs.length) return;

	const uniqueLogs = reportedIPs.reduce((acc, ip) => {
		if (acc.seen.has(ip.ip)) return acc;
		acc.seen.add(ip.ip);
		acc.logs.push(ip);
		return acc;
	}, { seen: new Set(), logs: [] }).logs;

	if (!uniqueLogs?.length) return log('log', 'No unique IPs to send to Sefinek API');

	try {
		const res = await axios.post(API_URL, {
			reportedIPs: uniqueLogs.map(ip => ({
				rayId: ip.rayId,
				ip: ip.ip,
				endpoint: ip.endpoint,
				useragent: ip.useragent.replace(/"/g, ''),
				action: ip.action,
				country: ip.country,
				timestamp: ip.timestamp,
			})),
		}, { headers: { 'Authorization': process.env.SEFINEK_API_SECRET } });

		log('log', `Successfully sent ${uniqueLogs.length} logs to Sefinek API. Status: ${res.status}`);

		uniqueLogs.forEach(ip => updateSefinekAPIInCSV(ip.rayId, true));
	} catch (err) {
		if (err.response?.data?.code !== 'NO_VALID_OR_UNIQUE_IPS') {
			log('error', `Failed to send logs to Sefinek API. Status: ${err.status}. Message: ${err.response?.data?.message || err.stack}`);
		}
	}
};