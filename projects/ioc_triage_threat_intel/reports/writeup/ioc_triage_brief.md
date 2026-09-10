# IOC Triage Threat Intelligence Brief

## Executive Summary

This analysis triaged **10 indicators of compromise** from sample SOC sources including email gateway, proxy, firewall, and EDR telemetry.

Priority breakdown:

- High: 1
- Medium: 4
- Low: 5

The highest-priority indicators are primarily related to credential phishing themes and endpoint file-hash investigation.

## Top Indicators

| indicator                                | type   | source        |   risk_score | priority   | threat_theme          |
|:-----------------------------------------|:-------|:--------------|-------------:|:-----------|:----------------------|
| http://secure-payroll-update.net/session | url    | email_gateway |           90 | high       | credential phishing   |
| 44d88612fea8a8f36de82e1278abb02f         | hash   | edr           |           65 | medium     | malware/file analysis |
| http://malicious-login-support.com/login | url    | email_gateway |           65 | medium     | credential phishing   |
| secure-payroll-update.net                | domain | email_gateway |           65 | medium     | credential phishing   |
| malicious-login-support.com              | domain | email_gateway |           50 | medium     | credential phishing   |

## Analyst Assessment

The strongest pattern is a small cluster of login/payroll-themed domains and URLs, which suggests a phishing campaign designed to harvest credentials. File hashes from EDR should be reviewed next to determine whether users downloaded or executed payloads from the phishing pages.

## Recommended Actions

1. Block high-priority domains and URLs at the email gateway, DNS layer, and proxy.
2. Search SIEM logs for all top indicators over the last 30 days.
3. Identify users who received or clicked phishing URLs.
4. Pull EDR process trees for hosts associated with suspicious hashes.
5. Convert confirmed indicators into detection rules and watchlists.

## Limitations

This project uses transparent local scoring logic instead of live enrichment APIs. In a production workflow, enrich indicators with VirusTotal, urlscan.io, AbuseIPDB, WHOIS, passive DNS, and internal SIEM context.
