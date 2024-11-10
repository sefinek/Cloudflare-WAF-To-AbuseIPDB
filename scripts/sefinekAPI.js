const { axios } = require('../services/axios.js');
const { readReportedIPs, updateSefinekAPIInCSV } = require('./csv.js');
const log = require('./log.js');
const clientIp = require('./clientIp.js');

const API_URL = `${process.env.SEFINEK_API_URL}/cloudflare-waf-abuseipdb/post`;

module.exports = async () => {
	const reportedIPs = readReportedIPs().filter(x =>
		x.status === 'REPORTED' &&
		x.ip !== clientIp.getAddress() &&
		!x.endpoint.includes('/api') && // API requests
		!['//video', '//js', '//images', '//imgs', 'favicon.ico'].some(endpoint => x.endpoint.includes(endpoint)) && // Endpoints
		['api.', 'cdn.'].some(prefix => x.hostname.startsWith(prefix)) && // Domains
		x.hostname !== 'blocklist.sefinek.net' && // Domain
		!['Chrome/129', 'Chrome/130', 'Chrome/131', 'Chrome/132', 'Chrome/133', 'StellaLauncher'].some(agent => x.useragent.includes(agent)) && // User-agents
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
		}, {
			headers: { 'Authorization': process.env.SEFINEK_API_SECRET },
		});

		log('log', `Successfully sent ${uniqueLogs.length} logs to Sefinek API. Status: ${res.status}`);

		uniqueLogs.forEach(ip => updateSefinekAPIInCSV(ip.rayId, true));
	} catch (err) {
		if (err.response?.data?.code !== 'NO_VALID_OR_UNIQUE_IPS') {
			log('error', `Failed to send logs to Sefinek API. Status: ${err.status}. Message: ${err.response?.data?.message || err.stack}`);
		}
	}
};