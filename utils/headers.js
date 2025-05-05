const { CLOUDFLARE_API_KEY, ABUSEIPDB_API_KEY } = require('../config.js').MAIN;

const CLOUDFLARE = {
	'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
};

const ABUSEIPDB = {
	'Key': ABUSEIPDB_API_KEY,
};

module.exports = { CLOUDFLARE, ABUSEIPDB };