const { MAIN } = require('../config.js').CONFIG;
const { version } = require('../package.json');

const UserAgent = `Mozilla/5.0 (compatible; Cloudflare-WAF-To-AbuseIPDB/${version}; +https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)`;

const CLOUDFLARE = {
	'User-Agent': UserAgent,
	'Content-Type': 'application/json',
	'Authorization': `Bearer ${MAIN.CLOUDFLARE_API_KEY}`,
};

const ABUSEIPDB = {
	'User-Agent': UserAgent,
	'Content-Type': 'application/json',
	'Key': MAIN.ABUSEIPDB_API_KEY,
};

module.exports = { UserAgent, CLOUDFLARE, ABUSEIPDB };