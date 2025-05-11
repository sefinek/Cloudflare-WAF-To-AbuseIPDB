const fs = require('node:fs/promises');
const path = require('node:path');
const { existsSync } = require('node:fs');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const log = require('../scripts/log.js');

const CSV_FILE = path.join(__dirname, '..', 'tmp', 'reported_ips.csv');
const MAX_CSV_SIZE = 4 * 1024 * 1024;

const CSV_COLUMNS = [
	'Timestamp',
	'CF RayID',
	'IP',
	'Country',
	'Hostname',
	'Endpoint',
	'User-Agent',
	'Action taken',
	'Status',
	'Sefinek API',
];

const ensureCSVExists = async () => {
	if (!existsSync(CSV_FILE)) {
		await fs.mkdir(path.dirname(CSV_FILE), { recursive: true });
		await fs.writeFile(CSV_FILE, stringify([], { header: true, columns: CSV_COLUMNS }));
		log(`Created missing CSV file: ${CSV_FILE}`, 1);
	}
};

const checkCSVSize = async () => {
	try {
		const stats = await fs.stat(CSV_FILE);
		if (stats.size > MAX_CSV_SIZE) {
			await fs.writeFile(CSV_FILE, stringify([], { header: true, columns: CSV_COLUMNS }));
			log(`CSV file exceeded ${MAX_CSV_SIZE / (1024 * 1024)} MB. Cleared.`, 1);
		}
	} catch (err) {
		log(`Failed to check CSV size: ${err.stack}`, 3, true);
	}
};

const logToCSV = async (event, status = 'N/A', sefinekAPI = false) => {
	await ensureCSVExists();
	await checkCSVSize();

	const {
		rayName, clientIP, clientCountryName,
		clientRequestHTTPHost, clientRequestPath,
		userAgent, action,
	} = event;

	const row = {
		'Timestamp': new Date().toISOString(),
		'CF RayID': rayName,
		'IP': clientIP,
		'Country': clientCountryName,
		'Hostname': clientRequestHTTPHost,
		'Endpoint': clientRequestPath,
		'User-Agent': userAgent,
		'Action taken': action.toUpperCase(),
		'Status': status,
		'Sefinek API': String(sefinekAPI),
	};

	try {
		const line = stringify([row], { header: false, columns: CSV_COLUMNS });
		await fs.appendFile(CSV_FILE, line);
	} catch (err) {
		log(`Failed to append to CSV: ${err.stack}`, 3, true);
	}
};

const readReportedIPs = async () => {
	if (!existsSync(CSV_FILE)) return [];

	try {
		const content = await fs.readFile(CSV_FILE, 'utf-8');
		const records = parse(content, {
			columns: true,
			skip_empty_lines: true,
			trim: true,
		});

		return records.map(row => ({
			timestamp: Date.parse(row['Timestamp']),
			rayId: row['CF RayID'],
			ip: row['IP'],
			country: row['Country'],
			hostname: row['Hostname'],
			endpoint: row['Endpoint'],
			userAgent: row['User-Agent'],
			action: row['Action taken'],
			status: row['Status'],
			sefinekAPI: row['Sefinek API'] === 'true',
		}));
	} catch (err) {
		log(`Failed to read CSV: ${err.stack}`, 3, true);
		return [];
	}
};

const updateSefinekAPIInCSV = async (rayId, reportedToSefinekAPI) => {
	if (!existsSync(CSV_FILE)) {
		log('CSV file does not exist', 2);
		return;
	}

	try {
		const content = await fs.readFile(CSV_FILE, 'utf-8');
		const records = parse(content, {
			columns: true,
			skip_empty_lines: true,
			trim: true,
		});

		let updated = false;
		for (const row of records) {
			if (row['CF RayID'] === rayId) {
				row['Sefinek API'] = String(reportedToSefinekAPI);
				updated = true;
			}
		}

		if (updated) {
			const output = stringify(records, { header: true, columns: CSV_COLUMNS });
			await fs.writeFile(CSV_FILE, output);
		}
	} catch (err) {
		log(`Failed to update CSV: ${err.stack}`, 3, true);
	}
};

module.exports = { logToCSV, readReportedIPs, updateSefinekAPIInCSV };