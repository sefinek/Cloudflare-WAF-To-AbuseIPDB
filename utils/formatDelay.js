const formatUnit = (value, unit) => {
	return value > 0 ? `${value} ${unit}${value !== 1 ? 's' : ''}` : '';
};

module.exports = ms => {
	const hours = Math.floor(ms / (1000 * 60 * 60));
	const minutes = Math.floor((ms / (1000 * 60)) % 60);
	const seconds = Math.floor((ms / 1000) % 60);

	const result = [];
	if (hours) result.push(formatUnit(hours, 'hour'));
	if (minutes) result.push(formatUnit(minutes, 'minute'));
	if (seconds) result.push(formatUnit(seconds, 'second'));

	return result.join(', ') || '0 seconds';
};