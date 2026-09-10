"""Analyze Zeek-style connection logs for suspicious network behavior."""

from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_DIR / "data" / "sample_logs" / "conn_sample.csv"
TABLE_DIR = PROJECT_DIR / "reports" / "tables"
REPORT_DIR = PROJECT_DIR / "reports" / "incident_writeups"

UNCOMMON_PORTS = {4444, 1337, 31337, 8081, 9001}
SCAN_REJECT_THRESHOLD = 5
BEACON_CONNECTION_THRESHOLD = 4
HIGH_BYTES_THRESHOLD = 50_000


def load_logs(path: Path = DATA_PATH) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["ts"])
    df["total_bytes"] = df["orig_bytes"] + df["resp_bytes"]
    return df


def summarize_by_source(df: pd.DataFrame) -> pd.DataFrame:
    return (
        df.groupby("id_orig_h", as_index=False)
        .agg(
            total_connections=("id_resp_h", "count"),
            unique_destinations=("id_resp_h", "nunique"),
            unique_ports=("id_resp_p", "nunique"),
            rejected_connections=("conn_state", lambda x: (x == "REJ").sum()),
            total_orig_bytes=("orig_bytes", "sum"),
            total_resp_bytes=("resp_bytes", "sum"),
        )
        .sort_values("total_connections", ascending=False)
    )


def detect_alerts(df: pd.DataFrame) -> pd.DataFrame:
    alerts = []

    source_summary = summarize_by_source(df)
    for _, row in source_summary.iterrows():
        if row["rejected_connections"] >= SCAN_REJECT_THRESHOLD and row["unique_destinations"] >= SCAN_REJECT_THRESHOLD:
            alerts.append(
                {
                    "severity": "high",
                    "source_ip": row["id_orig_h"],
                    "alert_type": "possible_port_or_service_scan",
                    "description": f"{row['rejected_connections']} rejected connections across {row['unique_destinations']} destinations.",
                    "mitre_attack": "T1046 - Network Service Discovery",
                }
            )

    uncommon = df[df["id_resp_p"].isin(UNCOMMON_PORTS)]
    for _, row in uncommon.iterrows():
        alerts.append(
            {
                "severity": "medium",
                "source_ip": row["id_orig_h"],
                "destination_ip": row["id_resp_h"],
                "destination_port": row["id_resp_p"],
                "alert_type": "connection_to_uncommon_port",
                "description": f"Connection to uncommon port {row['id_resp_p']} with {row['orig_bytes']} outbound bytes.",
                "mitre_attack": "T1071 - Application Layer Protocol",
            }
        )

    beacon_groups = (
        df.groupby(["id_orig_h", "id_resp_h", "id_resp_p"], as_index=False)
        .agg(
            connection_count=("ts", "count"),
            avg_duration=("duration", "mean"),
            avg_orig_bytes=("orig_bytes", "mean"),
        )
    )
    beacon_candidates = beacon_groups[
        (beacon_groups["connection_count"] >= BEACON_CONNECTION_THRESHOLD)
        & (beacon_groups["avg_orig_bytes"] >= HIGH_BYTES_THRESHOLD)
    ]

    for _, row in beacon_candidates.iterrows():
        alerts.append(
            {
                "severity": "high",
                "source_ip": row["id_orig_h"],
                "destination_ip": row["id_resp_h"],
                "destination_port": row["id_resp_p"],
                "alert_type": "possible_beaconing_or_data_exfiltration",
                "description": f"Repeated high-byte connections: {row['connection_count']} connections averaging {row['avg_orig_bytes']:.0f} outbound bytes.",
                "mitre_attack": "T1105 - Ingress Tool Transfer / C2-like behavior",
            }
        )

    return pd.DataFrame(alerts)


def write_incident_report(alerts: pd.DataFrame, source_summary: pd.DataFrame) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    high_count = int((alerts["severity"] == "high").sum()) if not alerts.empty else 0
    medium_count = int((alerts["severity"] == "medium").sum()) if not alerts.empty else 0

    report = f"""# Network Intrusion Detection Report

## Summary

The analysis identified **{len(alerts)} alerts** from the sample connection logs.

- High severity alerts: {high_count}
- Medium severity alerts: {medium_count}

## Top Source IPs

{source_summary.head(10).to_markdown(index=False)}

## Alerts

{alerts.to_markdown(index=False) if not alerts.empty else 'No alerts generated.'}

## Recommended Next Steps

1. Validate suspicious source IPs with endpoint logs.
2. Check DNS and proxy logs for the same time window.
3. Investigate uncommon destination ports and repeated high-byte outbound connections.
4. Tune thresholds against normal environment baselines.
5. Convert high-confidence detections into SIEM rules.
"""
    (REPORT_DIR / "network_intrusion_report.md").write_text(report, encoding="utf-8")


def main() -> None:
    TABLE_DIR.mkdir(parents=True, exist_ok=True)
    df = load_logs()
    source_summary = summarize_by_source(df)
    alerts = detect_alerts(df)

    source_summary.to_csv(TABLE_DIR / "source_ip_summary.csv", index=False)
    alerts.to_csv(TABLE_DIR / "alerts.csv", index=False)
    write_incident_report(alerts, source_summary)

    print(f"Generated {len(alerts)} alerts")
    print(alerts)


if __name__ == "__main__":
    main()
