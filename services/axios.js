const axios = require('axios');
const { version } = require('../package.json');

axios.defaults.headers.common['User-Agent'] = `Mozilla/5.0 (compatible; WAF-To-AbuseIPDB/${version}; +https://github.com/sefinek/Node-Cloudflare-WAF-AbuseIPDB)`;
axios.defaults.timeout = 12000;

module.exports = { axios, moduleVersion: version };