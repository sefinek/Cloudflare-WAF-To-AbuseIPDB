const axios = require('axios');
const { UserAgent } = require('../scripts/headers.js');
const { version } = require('../package.json');

axios.defaults.headers.common['User-Agent'] = UserAgent;
axios.defaults.timeout = 7000;

module.exports = { axios, moduleVersion: version };