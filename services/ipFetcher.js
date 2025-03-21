const { networkInterfaces } = require('node:os');
const https = require('node:https');
const { CronJob } = require('cron');
const { get } = require('./axios.js');
const isLocalIP = require('../utils/isLocalIP.js');
const log = require('../utils/log.js');
const { MAIN, CYCLES } = require('../config.js').CONFIG;

const ipAddresses = new Set();
let ipv6ErrorCount = 0, ipv6ErrorLogged = false;

const fetchIPAddress = async family => {
	if (family === 6 && (ipv6ErrorLogged || !MAIN.IPv6_SUPPORT)) return;

	try {
		const { data } = await get('https://api.sefinek.net/api/v2/ip', {
			httpsAgent: new https.Agent({ family }),
		});

		if (data?.success && data?.message) {
			ipAddresses.add(data.message);

			if (family === 6) {
				if (ipv6ErrorCount > 0) log(0, `Uh, it looks like IPv6 has started working! It only succeeded after ${ipv6ErrorCount} attempts.`);
				ipv6ErrorCount = 0;
			}
		} else {
			log(2, `Unexpected API response: ${JSON.stringify(data)}`);
		}
	} catch (err) {
		log(2, `Error fetching IPv${family} address: ${err.message}`);

		if (family === 6 && err.code === 'ENOENT') {
			ipv6ErrorCount++;

			if (ipv6ErrorCount >= 6 && !ipv6ErrorLogged) {
				ipv6ErrorLogged = true;
				log(0, 'It looks like your ISP hasn\'t assigned you any IPv6 address. I won\'t attempt to fetch it again.');
			} else {
				await new Promise(resolve => setTimeout(resolve, 4000));
				await fetchIPAddress(6);
			}
		}
	}
};

const fetchLocalIPs = () => {
	for (const iface of Object.values(networkInterfaces()).flat()) {
		if (iface && !iface.internal && iface.address && !isLocalIP(iface.address)) {
			ipAddresses.add(iface.address);
		}
	}
};

const refreshServerIPs = async () => {
	await Promise.all([fetchIPAddress(4), fetchIPAddress(6)]);
	fetchLocalIPs();
};

(async () => {
	new CronJob(CYCLES.IP_REFRESH_SCHEDULE || '0 */6 * * *', refreshServerIPs, null, true, 'UTC');
})();

module.exports = {
	refreshServerIPs,
	getServerIPs: () => [...ipAddresses],
};