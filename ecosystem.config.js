module.exports = {
	apps: [{
		name: 'waf',
		script: './index.js',

		// Configuration options
		exec_mode: 'fork',
		max_memory_restart: '500M',

		// Monitoring changes in files and restarting the application
		watch: false,
		ignore_watch: ['.git', 'node_modules', 'logs', 'eslint.config.mjs', 'ecosystem.config.js'],

		// Logging settings
		log_date_format: 'HH:mm:ss.SSS DD.MM.YYYY',
		merge_logs: true,
		log_file: '/home/sefinek/logs/other/waf-abuseipdb/combined.log',
		out_file: '/home/sefinek/logs/other/waf-abuseipdb/out.log',
		error_file: '/home/sefinek/logs/other/waf-abuseipdb/error.log',

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