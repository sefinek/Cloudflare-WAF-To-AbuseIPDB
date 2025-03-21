module.exports = {
	apps: [{
		name: 'cwa',
		script: './index.js',

		// Logging settings
		log_date_format: 'HH:mm:ss.SSS DD.MM.YYYY',
		merge_logs: true,
		log_file: '~/logs/other/cf-waf-abuseipdb/combined.log',
		out_file: '~/logs/other/cf-waf-abuseipdb/out.log',
		error_file: '~/logs/other/cf-waf-abuseipdb/error.log',

		// Application restart policy
		wait_ready: true,
		autorestart: true,
		max_restarts: 4,
		restart_delay: 4000,
		min_uptime: 3000,

		// Environment variables
		env: {
			NODE_ENV: 'production',
		},
	}],
};