const { MAIN } = require('../config.js').CONFIG;

const CLOUDFLARE = {
	'Authorization': `Bearer ${MAIN.CLOUDFLARE_API_KEY}`,
};

const ABUSEIPDB = {
	'Key': MAIN.ABUSEIPDB_API_KEY,
};

module.exports = { CLOUDFLARE, ABUSEIPDB };