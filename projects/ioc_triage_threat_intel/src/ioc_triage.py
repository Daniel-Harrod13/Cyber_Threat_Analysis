"""Simple IOC triage workflow for a threat intelligence analyst.

This project intentionally avoids paid API keys. It demonstrates the core analyst
workflow: normalize indicators, apply transparent scoring logic, assign priority,
map likely threat themes, and generate a short intelligence brief.
"""

from pathlib import Path
from urllib.parse import urlparse

import matplotlib.pyplot as plt
import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_DIR / "data" / "raw" / "sample_iocs.csv"
PROCESSED_DIR = PROJECT_DIR / "data" / "processed"
TABLE_DIR = PROJECT_DIR / "reports" / "tables"
FIGURE_DIR = PROJECT_DIR / "reports" / "figures"
WRITEUP_DIR = PROJECT_DIR / "reports" / "writeup"

SUSPICIOUS_TERMS = {
    "login": 20,
    "secure": 15,
    "payroll": 20,
    "update": 10,
    "support": 10,
    "session": 10,
    "verify": 15,
    "account": 15,
}

TEST_NET_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


def normalize_indicator(indicator: str, indicator_type: str) -> str:
    indicator = indicator.strip().lower()
    if indicator_type == "url":
        parsed = urlparse(indicator)
        return parsed.netloc.lower() + parsed.path.lower()
    return indicator


def extract_domain(indicator: str, indicator_type: str) -> str:
    if indicator_type == "url":
        return urlparse(indicator).netloc.lower()
    if indicator_type == "domain":
        return indicator.lower()
    return ""


def score_ioc(row: pd.Series) -> tuple[int, list[str], str]:
    indicator = row["normalized_indicator"]
    indicator_type = row["type"]
    score = 0
    reasons = []
    theme = "unknown"

    if indicator_type in {"domain", "url"}:
        for term, points in SUSPICIOUS_TERMS.items():
            if term in indicator:
                score += points
                reasons.append(f"contains suspicious term: {term}")

        if "login" in indicator or "payroll" in indicator:
            theme = "credential phishing"

        if indicator.count("-") >= 2:
            score += 10
            reasons.append("multiple hyphens in hostname/path")

        if indicator_type == "url" and ("/login" in indicator or "/session" in indicator):
            score += 15
            reasons.append("credential-themed URL path")

    elif indicator_type == "ip":
        if str(row["indicator"]).startswith(TEST_NET_PREFIXES):
            score += 5
            reasons.append("documentation-range IP used in sample data")
        else:
            score += 10
            reasons.append("external IP observed in logs")
        theme = "network infrastructure"

    elif indicator_type == "hash":
        score += 25
        reasons.append("file hash observed by endpoint telemetry")
        theme = "malware/file analysis"
        if indicator == "44d88612fea8a8f36de82e1278abb02f":
            score += 30
            reasons.append("known EICAR-style test hash placeholder")

    if row["source"] in {"email_gateway", "edr"}:
        score += 10
        reasons.append(f"high-value source: {row['source']}")

    return min(score, 100), reasons, theme


def priority(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def build_brief(df: pd.DataFrame) -> str:
    high = df[df["priority"] == "high"]
    medium = df[df["priority"] == "medium"]
    top = df.sort_values("risk_score", ascending=False).head(5)

    return f"""# IOC Triage Threat Intelligence Brief

## Executive Summary

This analysis triaged **{len(df)} indicators of compromise** from sample SOC sources including email gateway, proxy, firewall, and EDR telemetry.

Priority breakdown:

- High: {len(high)}
- Medium: {len(medium)}
- Low: {len(df) - len(high) - len(medium)}

The highest-priority indicators are primarily related to credential phishing themes and endpoint file-hash investigation.

## Top Indicators

{top[['indicator', 'type', 'source', 'risk_score', 'priority', 'threat_theme']].to_markdown(index=False)}

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
"""


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    TABLE_DIR.mkdir(parents=True, exist_ok=True)
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    WRITEUP_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(DATA_PATH)
    df["normalized_indicator"] = df.apply(lambda r: normalize_indicator(r["indicator"], r["type"]), axis=1)
    df["domain"] = df.apply(lambda r: extract_domain(r["indicator"], r["type"]), axis=1)

    scored = df.apply(score_ioc, axis=1, result_type="expand")
    df["risk_score"] = scored[0]
    df["reasons"] = scored[1].apply(lambda reasons: "; ".join(reasons))
    df["threat_theme"] = scored[2]
    df["priority"] = df["risk_score"].apply(priority)

    df = df.sort_values(["risk_score", "indicator"], ascending=[False, True])

    df.to_csv(PROCESSED_DIR / "triaged_iocs.csv", index=False)
    df.to_csv(TABLE_DIR / "triaged_iocs.csv", index=False)

    summary = df.groupby(["priority", "type"], as_index=False).size()
    summary.to_csv(TABLE_DIR / "ioc_summary.csv", index=False)

    plt.figure(figsize=(8, 5))
    df["priority"].value_counts().reindex(["high", "medium", "low"]).fillna(0).plot(kind="bar")
    plt.title("IOC Priority Breakdown")
    plt.xlabel("Priority")
    plt.ylabel("Indicator count")
    plt.tight_layout()
    plt.savefig(FIGURE_DIR / "ioc_priority_breakdown.png", dpi=300)
    plt.close()

    (WRITEUP_DIR / "ioc_triage_brief.md").write_text(build_brief(df), encoding="utf-8")

    print(f"Triaged {len(df)} IOCs")
    print(df[["indicator", "type", "risk_score", "priority", "threat_theme"]])


if __name__ == "__main__":
    main()
