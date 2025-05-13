const { CLOUDFLARE_API_KEY, ABUSEIPDB_API_KEY, SEFIN_API_SECRET_TOKEN } = require('../config.js').MAIN;

const CLOUDFLARE = {
	'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
};

const ABUSEIPDB = {
	'Key': ABUSEIPDB_API_KEY,
};

const SEFINEK_API = {
	'X-API-Key': SEFIN_API_SECRET_TOKEN,
};

module.exports = { CLOUDFLARE, ABUSEIPDB, SEFINEK_API };