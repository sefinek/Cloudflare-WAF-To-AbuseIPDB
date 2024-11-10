const { name, version, homepage } = require('../package.json');

const UserAgent = `Mozilla/5.0 (compatible; ${name}/${version}; +${homepage})`;

const CLOUDFLARE = {
	'User-Agent': UserAgent,
	'Content-Type': 'application/json',
	'Authorization': `Bearer ${process.env.CLOUDFLARE_API_KEY}`,
};

const ABUSEIPDB = {
	'User-Agent': UserAgent,
	'Content-Type': 'application/json',
	'Key': process.env.ABUSEIPDB_API_KEY,
};

module.exports = { UserAgent, CLOUDFLARE, ABUSEIPDB };