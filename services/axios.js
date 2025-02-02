const axios = require('axios');
const { UserAgent } = require('../utils/headers.js');

axios.defaults.headers.common = {
	'User-Agent': UserAgent,
	'Accept': 'application/json',
	'Cache-Control': 'no-cache',
	'Connection': 'keep-alive',
};

axios.defaults.timeout = 30000;

module.exports = axios;