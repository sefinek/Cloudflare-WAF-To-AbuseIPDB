module.exports = (limit, zoneTag) => {
	if (!zoneTag) throw new Error('zoneTag is null or undefined');

	const variables = {
		zoneTag,
		filter: {
			datetime_geq: new Date(Date.now() - (60 * 60 * 12 * 1000)).toISOString(),
			AND: [
				{ action_neq: 'allow' },
				{ action_neq: 'skip' },
				{ action_neq: 'challenge_solved' },
				{ action_neq: 'challenge_failed' },
				{ action_neq: 'challenge_bypassed' },
				{ action_neq: 'jschallenge_solved' },
				{ action_neq: 'jschallenge_failed' },
				{ action_neq: 'jschallenge_bypassed' },
				{ action_neq: 'managed_challenge_skipped' },
				{ action_neq: 'managed_challenge_non_interactive_solved' },
				{ action_neq: 'managed_challenge_interactive_solved' },
				{ action_neq: 'managed_challenge_bypassed' },
			],
		},
	};

	return { query: `
query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      firewallEventsAdaptive(
        filter: $filter,
        limit: ${limit},
        orderBy: [datetime_DESC]
      ) {
        action
        clientASNDescription
        clientAsn
        clientCountryName
        clientIP
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestHTTPProtocol
        clientRequestPath
        clientRequestQuery
        datetime
        rayName
        ruleId
        source
        userAgent
      }
    }
  }
}`, variables };
};