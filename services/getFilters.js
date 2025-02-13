const axios = require('./axios.js');

module.exports = async () => {
	try {
		const res = await axios.get('https://api.sefinek.net/api/v2/filter-rules');
		if (!res.data.success) throw new Error('Sefinek API Error');
		return { userAgents: res.data.userAgents, domains: res.data.domains, endpoints: res.data.endpoints, imgExtensions: res.data.imgExtensions };
	} catch (err) {
		throw new Error(err);
	}
};