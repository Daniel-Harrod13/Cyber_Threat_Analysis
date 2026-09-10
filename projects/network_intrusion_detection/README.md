# Network Intrusion Detection from Connection Logs

## Executive Summary

This project analyzes Zeek-style network connection logs to identify suspicious behavior. It is designed as an entry-level but portfolio-ready threat hunting workflow that combines data analysis, detection rules, MITRE ATT&CK mapping, and incident-style reporting.

## Analysis Question

> Can we identify suspicious network activity from connection logs and explain the findings in a way useful to a security operations team?

## Detection Goals

This project looks for:

- Port scanning behavior
- High-volume outbound connections
- Connections to uncommon ports
- Repeated failed or rejected connections
- Potential command-and-control style beaconing indicators

## Data

The project includes a small synthetic Zeek-style sample log for reproducibility:

```text
data/sample_logs/conn_sample.csv
```

The sample data is safe and intentionally fabricated for analysis practice.

## Methods

- Parse connection logs with pandas
- Build summary statistics by source IP, destination IP, and port
- Flag suspicious patterns with transparent detection logic
- Map findings to MITRE ATT&CK techniques
- Export alerts and a short incident report

## How to Run

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python projects/network_intrusion_detection/src/analyze_connections.py
```

## Outputs

```text
projects/network_intrusion_detection/reports/tables/alerts.csv
projects/network_intrusion_detection/reports/tables/source_ip_summary.csv
projects/network_intrusion_detection/reports/incident_writeups/network_intrusion_report.md
```

## MITRE ATT&CK Mapping

| Suspicious Pattern | Possible Technique |
|---|---|
| Port scanning | T1046 - Network Service Discovery |
| Unusual outbound connection volume | T1071 - Application Layer Protocol |
| Repeated rejected connections | T1046 - Network Service Discovery |
| Beacon-like repeated connections | T1105 - Ingress Tool Transfer / C2-like behavior |

## Limitations

- Uses synthetic sample data
- Detection thresholds are simple and should be tuned for real environments
- Connection logs alone do not prove compromise
- Findings should be validated with endpoint, DNS, proxy, and authentication logs
