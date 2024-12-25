const { axios } = require('./axios.js');
const { IP_REFRESH_INTERVAL } = require('../scripts/config.js');
const log = require('../scripts/log.js');

let address = null; // Holds the IP address

const fetchIPAddress = async () => {
	try {
		const { data } = await axios.get('https://api.sefinek.net/api/v2/ip');
		if (data?.success) {
			address = data.message;
		} else {
			log(2, 'Failed to retrieve your IP');
		}
	} catch (err) {
		log(2, 'Error fetching your IP:', err.stack);
	}
};


setInterval(fetchIPAddress, IP_REFRESH_INTERVAL);

module.exports = { fetchIPAddress, getAddress: () => address };