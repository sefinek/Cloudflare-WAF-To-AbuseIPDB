const fs = require('node:fs/promises');
const path = require('node:path');
const { existsSync } = require('node:fs');
const log = require('../../scripts/log.js');

const CSV_FILE_PATH = path.join(__dirname, '..', '..', 'tmp', 'reported_ips.csv');
const MAX_CSV_SIZE_BYTES = 4 * 1024 * 1024; // 4 MB
const CSV_HEADER = 'Timestamp,CF RayID,IP,Country,Hostname,Endpoint,User-Agent,Action taken,Status,Sefinek API\n';

const initializeTmpFile = async () => {
	try {
		await fs.access(CSV_FILE_PATH);
	} catch (err) {
		if (err.code === 'ENOENT') {
			await fs.mkdir(path.dirname(CSV_FILE_PATH), { recursive: true });
			await fs.writeFile(CSV_FILE_PATH, CSV_HEADER);
			log(`Created missing CSV file: ${CSV_FILE_PATH}`, 1);
			return;
		}

		throw err;
	}
};

const checkCSVSize = async () => {
	try {
		const stats = await fs.stat(CSV_FILE_PATH);
		if (stats.size > MAX_CSV_SIZE_BYTES) {
			await fs.writeFile(CSV_FILE_PATH, CSV_HEADER);
			log(`The CSV file size exceeded ${MAX_CSV_SIZE_BYTES / (1024 * 1024)} MB. Cleared.`, 1);
		}
	} catch (err) {
		log(`Failed to check CSV size: ${err.stack}`, 3, true);
	}
};

const escapeCSVValue = value => {
	if (typeof value === 'string' && value.includes(',')) {
		return `"${value.replace(/"/g, '""')}"`;
	}
	return value || '';
};

const logToCSV = async (event, status = 'N/A', sefinekAPI = false) => {
	await initializeTmpFile();
	await checkCSVSize();

	const {
		rayName, clientIP, clientCountryName, clientRequestHTTPHost,
		clientRequestPath, userAgent, action,
	} = event;

	const logLine = `${new Date().toISOString()},${rayName},${clientIP},${clientCountryName},${clientRequestHTTPHost},${escapeCSVValue(clientRequestPath)},${escapeCSVValue(userAgent)},${action.toUpperCase()},${status},${sefinekAPI}`;

	try {
		await fs.appendFile(CSV_FILE_PATH, logLine + '\n');
	} catch (err) {
		log(`Failed to append to CSV: ${err.stack}`, 3, true);
	}
};

const readReportedIPs = async () => {
	if (!existsSync(CSV_FILE_PATH)) return [];

	try {
		const content = await fs.readFile(CSV_FILE_PATH, 'utf-8');

		const lines = content
			.split('\n')
			.filter(line => line.trim() !== '');

		const header = lines[0];
		const entries = lines.slice(1)
			.map(line => {
				const parts = line.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/g);
				if (parts.length < 9) return null;

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
					raw: line,
				};
			})
			.filter(e => e);

		const updated = [header, ...entries.map(e => e.raw)].join('\n');
		await fs.writeFile(CSV_FILE_PATH, updated + '\n');

		return entries.map(({ ...rest }) => rest);
	} catch (err) {
		log(`Failed to read CSV: ${err.stack}`, 3, true);
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
		const updatedLines = content.split('\n').map(line => {
			const parts = line.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/g);
			if (parts.length >= 9 && parts[1] === rayId) {
				parts[9] = reportedToSefinekAPI;
				return parts.join(',');
			}
			return line;
		});

		await fs.writeFile(CSV_FILE_PATH, updatedLines.join('\n'));
	} catch (err) {
		log(`Failed to update CSV: ${err.stack}`, 3, true);
	}
};

module.exports = { logToCSV, readReportedIPs, updateSefinekAPIInCSV };