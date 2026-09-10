# Network Intrusion Detection Report

## Summary

The analysis identified **7 alerts** from the sample connection logs.

- High severity alerts: 2
- Medium severity alerts: 5

## Top Source IPs

| id_orig_h   |   total_connections |   unique_destinations |   unique_ports |   rejected_connections |   total_orig_bytes |   total_resp_bytes |
|:------------|--------------------:|----------------------:|---------------:|-----------------------:|-------------------:|-------------------:|
| 10.0.1.44   |                   8 |                     8 |              2 |                      8 |                480 |                  0 |
| 10.0.1.22   |                   5 |                     1 |              1 |                      0 |               6000 |              49050 |
| 10.0.1.80   |                   5 |                     1 |              1 |                      0 |             448700 |               6075 |
| 10.0.1.15   |                   2 |                     2 |              2 |                      0 |               1050 |               5600 |

## Alerts

| severity   | source_ip   | alert_type                              | description                                                                   | mitre_attack                                     | destination_ip   |   destination_port |
|:-----------|:------------|:----------------------------------------|:------------------------------------------------------------------------------|:-------------------------------------------------|:-----------------|-------------------:|
| high       | 10.0.1.44   | possible_port_or_service_scan           | 8 rejected connections across 8 destinations.                                 | T1046 - Network Service Discovery                | nan              |                nan |
| medium     | 10.0.1.80   | connection_to_uncommon_port             | Connection to uncommon port 4444 with 90000 outbound bytes.                   | T1071 - Application Layer Protocol               | 192.0.2.99       |               4444 |
| medium     | 10.0.1.80   | connection_to_uncommon_port             | Connection to uncommon port 4444 with 88000 outbound bytes.                   | T1071 - Application Layer Protocol               | 192.0.2.99       |               4444 |
| medium     | 10.0.1.80   | connection_to_uncommon_port             | Connection to uncommon port 4444 with 91000 outbound bytes.                   | T1071 - Application Layer Protocol               | 192.0.2.99       |               4444 |
| medium     | 10.0.1.80   | connection_to_uncommon_port             | Connection to uncommon port 4444 with 89500 outbound bytes.                   | T1071 - Application Layer Protocol               | 192.0.2.99       |               4444 |
| medium     | 10.0.1.80   | connection_to_uncommon_port             | Connection to uncommon port 4444 with 90200 outbound bytes.                   | T1071 - Application Layer Protocol               | 192.0.2.99       |               4444 |
| high       | 10.0.1.80   | possible_beaconing_or_data_exfiltration | Repeated high-byte connections: 5 connections averaging 89740 outbound bytes. | T1105 - Ingress Tool Transfer / C2-like behavior | 192.0.2.99       |               4444 |

## Recommended Next Steps

1. Validate suspicious source IPs with endpoint logs.
2. Check DNS and proxy logs for the same time window.
3. Investigate uncommon destination ports and repeated high-byte outbound connections.
4. Tune thresholds against normal environment baselines.
5. Convert high-confidence detections into SIEM rules.
