const fs = require('node:fs/promises');
const path = require('node:path');
const { existsSync } = require('node:fs');
const log = require('../../scripts/log.js');
const { dirname } = require('node:path');

const CSV_FILE_PATH = path.join(__dirname, '..', '..', 'tmp', 'reported_ips.csv');
const MAX_CSV_SIZE_BYTES = 4 * 1024 * 1024; // 4 MB
const CSV_HEADER = 'Timestamp,CF RayID,IP,Country,Hostname,Endpoint,User-Agent,Action taken,Status,Sefinek API\n';

const ensureCacheDir = async () => {
	const dir = dirname(CSV_FILE_PATH);
	try {
		await fs.access(dir);
	} catch (err) {
		if (err.code === 'ENOENT') {
			await fs.mkdir(dir, { recursive: true });
			log(`Created cache directory: ${dir}`, 1);
		} else {
			log(`Failed to access cache directory: ${err.message}`, 3);
		}
	}
};

const checkCSVSize = async () => {
	try {
		const stats = await fs.stat(CSV_FILE_PATH);
		if (stats.size > MAX_CSV_SIZE_BYTES) {
			await fs.writeFile(CSV_FILE_PATH, CSV_HEADER);
			log(`The CSV file size exceeded ${MAX_CSV_SIZE_BYTES / (1024 * 1024)} MB. To save memory, its contents have been removed.`, 1);
		}
	} catch (err) {
		log(`Failed to check CSV file size: ${err.message}`, 3, true);
	}
};

const escapeCSVValue = value => {
	if (typeof value === 'string' && value.includes(',')) return `"${value.replace(/"/g, '""')}"`;
	return value || '';
};

const logToCSV = async (rayId, ip, country = 'N/A', hostname, endpoint, userAgent, actionTaken = 'N/A', status = 'N/A', sefinekAPI) => {
	await ensureCacheDir();
	await checkCSVSize();

	const logLine = `${new Date().toISOString()},${rayId},${ip},${country},${hostname},${escapeCSVValue(endpoint)},${escapeCSVValue(userAgent)},${actionTaken.toUpperCase()},${status},${sefinekAPI || false}`;
	try {
		await fs.appendFile(CSV_FILE_PATH, logLine + '\n');
	} catch (err) {
		log(`Failed to append to CSV: ${err.message}`, 3, true);
	}
};

const readReportedIPs = async () => {
	if (!existsSync(CSV_FILE_PATH)) return [];

	try {
		const content = await fs.readFile(CSV_FILE_PATH, 'utf-8');
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
	} catch (err) {
		log(`Failed to read CSV: ${err.message}`, 3, true);
		return [];
	}
};

const updateSefinekAPIInCSV = async (rayId, reportedToSefinekAPI) => {
	if (!existsSync(CSV_FILE_PATH)) {
		log('CSV file does not exist', 2);
		return;
	}

	try {
		const content = await fs.readFile(CSV_FILE_PATH, 'utf-8');
		const lines = content.split('\n');

		const updatedLines = lines.map(line => {
			const parts = line.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/g);
			if (parts.length >= 9 && parts[1] === rayId) {
				parts[9] = reportedToSefinekAPI;
				return parts.join(',');
			}
			return line;
		});

		await fs.writeFile(CSV_FILE_PATH, updatedLines.join('\n'));
	} catch (err) {
		log(`Failed to update CSV: ${err.message}`, 3, true);
	}
};

module.exports = { logToCSV, readReportedIPs, updateSefinekAPIInCSV };