const CYCLE_INTERVAL = process.env.NODE_ENV === 'production' ?
	parseInt(process.env.CYCLE_INTERVAL || '120') * 60 * 1000 : 8 * 1000;

const REPORTED_IP_COOLDOWN_MS = parseInt(process.env.REPORTED_IP_COOLDOWN_MS || '6') * 60 * 60 * 1000;

const MAX_URL_LENGTH = parseInt(process.env.MAX_URL_LENGTH || '920');

const SUCCESS_COOLDOWN = parseInt(process.env.SUCCESS_COOLDOWN || '200');

const IP_REFRESH_INTERVAL = parseInt(process.env.IP_REFRESH_INTERVAL || '80') * 60 * 1000;

const REPORT_TO_SEFINEK_API = process.env.REPORT_TO_SEFINEK_API === 'true';

const SEFINEK_API_INTERVAL = process.env.NODE_ENV === 'production' ?
	parseInt(process.env.SEFINEK_API_INTERVAL || '1') * 60 * 60 * 1000 : 5 * 1000;

module.exports = {
	CYCLE_INTERVAL,
	REPORTED_IP_COOLDOWN_MS,
	MAX_URL_LENGTH,
	SUCCESS_COOLDOWN,
	IP_REFRESH_INTERVAL,
	REPORT_TO_SEFINEK_API,
	SEFINEK_API_INTERVAL,
};