# Threat Intelligence IOC Triage Workflow

1. **Collect** indicators from alerts, emails, firewall logs, EDR, proxy logs, or public reports.
2. **Normalize** indicators so duplicate forms are easier to compare.
3. **Enrich** with source context, reputation, WHOIS, passive DNS, malware sandboxes, and internal telemetry.
4. **Score** indicators using severity, confidence, source reliability, and observed activity.
5. **Prioritize** into high, medium, and low action groups.
6. **Action** high-confidence indicators through blocking, hunting, or escalation.
7. **Communicate** findings in a short intelligence brief.

This project implements a simplified local version of that workflow without external APIs.
