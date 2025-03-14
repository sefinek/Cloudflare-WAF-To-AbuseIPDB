const { networkInterfaces } = require('node:os');
const { get } = require('./axios.js');
const isLocalIP = require('../utils/isLocalIP.js');
const log = require('../utils/log.js');
const { CYCLES } = require('../config.js').CONFIG;

const ipAddrList = new Set();

const fetchIPv4Address = async () => {
	try {
		const { data } = await get('https://api.sefinek.net/api/v2/ip');
		if (data?.success && data?.message) ipAddrList.add(data.message);
	} catch (err) {
		log(2, `Error fetching IPv4 address: ${err.message}`);
	}
};

const fetchIPv6Address = () => {
	try {
		Object.values(networkInterfaces()).flat().forEach(({ address, internal }) => {
			if (!internal && address && !isLocalIP(address)) ipAddrList.add(address);
		});
	} catch (err) {
		log(2, `Error fetching IPv6 address: ${err.message}`);
	}
};

const fetchServerIPs = async () => {
	ipAddrList.clear();
	await fetchIPv4Address();
	fetchIPv6Address();
};

(async () => {
	await fetchServerIPs();
	setInterval(fetchServerIPs, CYCLES.IP_REFRESH_INTERVAL);

	// console.debug(ipAddrList);
})();

module.exports = () => Array.from(ipAddrList);