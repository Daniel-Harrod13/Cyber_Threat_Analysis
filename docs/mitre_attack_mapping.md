# MITRE ATT&CK Mapping Notes

Use this document to connect technical detections to attacker behaviors.

## Common Network Threat Hunting Mappings

| Behavior | MITRE Technique | Notes |
|---|---|---|
| Port or service scanning | T1046 - Network Service Discovery | Often appears as many connection attempts across ports or hosts |
| Repeated outbound traffic to one host | T1071 - Application Layer Protocol | Could be normal app behavior or C2; validate with DNS/proxy/endpoint logs |
| Data transfer to unusual host/port | T1041 - Exfiltration Over C2 Channel | Requires evidence of data movement and suspicious destination |
| Tool download from remote host | T1105 - Ingress Tool Transfer | Look for downloads followed by execution telemetry |
| Lateral movement over SMB/RDP/SSH | T1021 - Remote Services | Validate with authentication logs and endpoint process data |

## Portfolio Tip

For each project, include a small table with:

1. Detection name
2. Evidence observed
3. MITRE mapping
4. Confidence level
5. Recommended analyst action
