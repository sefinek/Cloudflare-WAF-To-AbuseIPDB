'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { existsSync } = require('node:fs');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const logger = require('../scripts/logger.js');

const CSV_FILE = path.join(__dirname, '..', 'tmp', 'reported_ips.csv');
const CSV_COLUMNS = ['Timestamp', 'CF RayID', 'IP', 'Country', 'Hostname', 'Endpoint', 'User-Agent', 'Action taken', 'Status', 'Sefinek API'];
const MAX_CSV_SIZE = 1024 * 1024;

const CSV_STRINGIFY_OPTS = {
	header: true,
	columns: CSV_COLUMNS,
	record_delimiter: '\n',
	quoted: true,
	quoted_empty: true,
	quoted_string: true,
};

const CSV_PARSE_OPTS = {
	columns: true,
	skip_empty_lines: true,
	trim: true,
	skip_records_with_empty_values: false,
};

const ensureCSVExists = async () => {
	try {
		if (existsSync(CSV_FILE)) return;
		await fs.mkdir(path.dirname(CSV_FILE), { recursive: true });
		await fs.writeFile(CSV_FILE, stringify([], CSV_STRINGIFY_OPTS));
		logger.log(`Created missing CSV file: ${CSV_FILE}`, 1);
	} catch (err) {
		logger.log(`Failed to ensure CSV exists: ${err.stack}`, 3, true);
		throw err;
	}
};

const checkCSVSize = async () => {
	try {
		if (!existsSync(CSV_FILE)) return;
		const stats = await fs.stat(CSV_FILE);

		if (stats.size > MAX_CSV_SIZE) {
			const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
			const backupPath = `${CSV_FILE}.${timestamp}.bkp`;

			await fs.copyFile(CSV_FILE, backupPath);
			await fs.writeFile(CSV_FILE, stringify([], CSV_STRINGIFY_OPTS));
			logger.log(`CSV size limit exceeded (${(MAX_CSV_SIZE / (1024 * 1024)).toFixed(2)} MB). Backup saved as "${path.basename(backupPath)}", original file cleared.`, 1);
		}
	} catch (err) {
		logger.log(`Failed to check or clear CSV size: ${err.stack}`, 3, true);
	}
};

const logToCSV = async (event, status = 'N/A', sefinekAPI = false) => {
	try {
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

		const line = stringify([row], { ...CSV_STRINGIFY_OPTS, header: false });
		await fs.appendFile(CSV_FILE, line);
	} catch (err) {
		logger.log(`Failed to log event to CSV: ${err.stack}`, 3, true);
	}
};

const readReportedIPs = async () => {
	if (!existsSync(CSV_FILE)) return [];

	try {
		const content = await fs.readFile(CSV_FILE, 'utf-8');
		const records = parse(content, CSV_PARSE_OPTS);

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
		logger.log(`Failed to parse or map CSV content: ${err.stack}`, 3, true);
		return [];
	}
};

const batchUpdateSefinekAPIInCSV = async (rayIds = []) => {
	if (!existsSync(CSV_FILE) || !rayIds.length) return;

	try {
		const content = await fs.readFile(CSV_FILE, 'utf-8');
		const records = parse(content, CSV_PARSE_OPTS);

		const raySet = new Set(rayIds);
		let updated = false;

		for (const row of records) {
			if (raySet.has(row['CF RayID']) && row['Sefinek API'] !== 'true') {
				row['Sefinek API'] = 'true';
				updated = true;
			}
		}

		if (updated) {
			const output = stringify(records, CSV_STRINGIFY_OPTS);
			await fs.writeFile(CSV_FILE, output);
		}
	} catch (err) {
		logger.log(`Batch CSV update failed: ${err.stack}`, 3, true);
	}
};

module.exports = Object.freeze({
	logToCSV,
	readReportedIPs,
	batchUpdateSefinekAPIInCSV,
});