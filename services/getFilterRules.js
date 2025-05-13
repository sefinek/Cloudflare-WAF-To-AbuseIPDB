const { axios } = require('../scripts/services/axios.js');
const logger = require('../scripts/logger.js');

module.exports = async () => {
	try {
		const res = await axios.get('https://api.sefinek.net/api/v2/filter-rules');
		const data = res.data;
		if (!data.success || typeof data !== 'object') {
			throw new Error(`Sefinek API error: Invalid response (success=${data.success})`);
		}

		const { userAgents, domains, endpoints, imgExtensions, lastUpdate } = data;
		if (!Array.isArray(userAgents) || !Array.isArray(domains) || !Array.isArray(endpoints) || !Array.isArray(imgExtensions)) {
			throw new Error('Sefinek API error: Response is missing expected arrays');
		}

		logger.log(`Filter rules loaded from api.sefinek.net, last update: ${lastUpdate}`, 1);
		return { userAgents, domains, endpoints, imgExtensions, lastUpdate };
	} catch (err) {
		throw new Error(`Failed to fetch filter rules: ${err.message}`);
	}
};