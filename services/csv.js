const fs = require('node:fs');
const path = require('node:path');
const log = require('../utils/log.js');

const CSV_FILE_PATH = path.join(__dirname, '..', 'reported_ips.csv');
const MAX_CSV_SIZE_BYTES = 3 * 1024 * 1024; // 3 MB
const CSV_HEADER = 'Timestamp,CF RayID,IP,Country,Hostname,Endpoint,User-Agent,Action taken,Status,Sefinek API\n';

if (!fs.existsSync(CSV_FILE_PATH)) fs.writeFileSync(CSV_FILE_PATH, CSV_HEADER);

const checkCSVSize = () => {
	const stats = fs.statSync(CSV_FILE_PATH);
	if (stats.size > MAX_CSV_SIZE_BYTES) {
		fs.writeFileSync(CSV_FILE_PATH, CSV_HEADER);
		log(0, `CSV file size exceeded ${MAX_CSV_SIZE_BYTES / (1024 * 1024)} MB. File has been reset.`);
	}
};

const escapeCSVValue = value => {
	if (typeof value === 'string' && value.includes(',')) return `"${value.replace(/"/g, '""')}"`;
	return value || '';
};

const logToCSV = (rayId, ip, country = 'N/A', hostname, endpoint, userAgent, actionTaken = 'N/A', status = 'N/A', sefinekAPI) => {
	checkCSVSize();
	const logLine = `${new Date().toISOString()},${rayId},${ip},${country},${hostname},${escapeCSVValue(endpoint)},${escapeCSVValue(userAgent)},${actionTaken.toUpperCase()},${status},${sefinekAPI || false}`;
	fs.appendFileSync(CSV_FILE_PATH, logLine + '\n');
};

const readReportedIPs = () => {
	if (!fs.existsSync(CSV_FILE_PATH)) return [];

	const content = fs.readFileSync(CSV_FILE_PATH, 'utf-8');
	return content
		.split('\n')
		.slice(1)
		.filter(line => line.trim() !== '')
		.map(line => {
			const parts = line.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/g);
			if (!parts || parts.length < 9) return null;

			return {
				timestamp: Date.parse(parts[0]),
				rayId: parts[1],
				ip: parts[2],
				country: parts[3],
				hostname: parts[4],
				endpoint: parts[5],
				userAgent: parts[6].replace(/(^"|"$)/g, ''),
				action: parts[7],
				status: parts[8],
				sefinekAPI: parts[9] === 'true',
			};
		})
		.filter(item => item !== null);
};

const updateSefinekAPIInCSV = (rayId, reportedToSefinekAPI) => {
	if (!fs.existsSync(CSV_FILE_PATH)) {
		log(2, 'CSV file does not exist');
		return;
	}

	const content = fs.readFileSync(CSV_FILE_PATH, 'utf-8');
	const lines = content.split('\n');

	const updatedLines = lines.map(line => {
		const parts = line.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/g);
		if (parts.length >= 9 && parts[1] === rayId) {
			parts[9] = reportedToSefinekAPI;
			return parts.join(',');
		}
		return line;
	});

	fs.writeFileSync(CSV_FILE_PATH, updatedLines.join('\n'));
};

const wasImageRequestLogged = (ip, reportedIPs) => reportedIPs.some(entry => entry.ip === ip && entry.action === 'SKIPPED_IMAGE_REQUEST');

module.exports = { logToCSV, readReportedIPs, updateSefinekAPIInCSV, wasImageRequestLogged };