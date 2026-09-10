# Cyber Threat Analysis Portfolio

This repository is a portfolio and working hub for cyber threat analysis projects, detection engineering templates, log analysis workflows, and incident-style reporting.

## Purpose

The goal is to demonstrate practical cybersecurity analysis skills across:

- Network traffic investigation
- Log parsing and anomaly detection
- Detection engineering
- MITRE ATT&CK mapping
- Incident report writing
- Threat intelligence enrichment
- Reproducible Python analysis workflows

## Repository Structure

```text
Cyber_Threat_Analysis/
├── projects/
│   └── network_intrusion_detection/
├── templates/
│   ├── incident_report/
│   ├── log_analysis/
│   ├── sigma_rules/
│   └── yara_rules/
├── src/
│   ├── parsers/
│   ├── detection/
│   ├── enrichment/
│   └── visualization/
├── datasets/
├── reports/
└── docs/
```

## Featured Projects

### IOC Triage for Threat Intelligence

A simple first project for a threat intelligence analyst. It normalizes sample indicators of compromise, applies transparent risk scoring, prioritizes IOCs, and generates an analyst-style intelligence brief.

Project folder:

```text
projects/ioc_triage_threat_intel/
```

### Network Intrusion Detection from Connection Logs

A starter threat hunting project that analyzes Zeek-style network connection logs to identify suspicious activity such as scanning, high-volume outbound traffic, uncommon ports, and possible command-and-control patterns.

Project folder:

```text
projects/network_intrusion_detection/
```

## Tools and Techniques

- Python
- pandas
- scikit-learn
- matplotlib / seaborn
- Sigma-style detection logic
- MITRE ATT&CK framework
- Incident reporting

## Portfolio Direction

Planned projects may include:

1. Network intrusion detection
2. Phishing email analysis
3. Malware traffic analysis
4. Threat intelligence dashboard
5. SIEM alert triage simulation
6. Cloud security log analysis
