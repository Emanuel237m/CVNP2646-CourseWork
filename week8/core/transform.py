# core/transform.py

from datetime import datetime


def transform_to_firewall(indicators):
    """
    Transform indicators into a firewall blocklist format.
    """

    entries = []

    for ind in indicators:
        entry = {
            "address": ind["value"],
            "action": "block",
            "priority": "high" if ind["threat_level"] == "critical" else "medium",
            "reason": f"Threat level: {ind['threat_level']}, Confidence: {ind['confidence']}%",
            "sources": ind["sources"]
        }
        entries.append(entry)

    return {
        "generated_at": datetime.now().isoformat(),
        "total_entries": len(entries),
        "blocklist": entries
    }


def transform_to_siem(indicators):
    """
    Transform indicators into a SIEM-friendly JSON format.
    """

    siem_entries = []

    for ind in indicators:
        entry = {
            "ioc_type": ind["type"],
            "ioc_value": ind["value"],
            "siem_severity": ind["threat_level"],
            "confidence_score": ind["confidence"],
            "seen_first": ind["first_seen"],
            "vendors": ind["sources"],
        }
        siem_entries.append(entry)

    return {
        "generated_at": datetime.now().isoformat(),
        "total_iocs": len(siem_entries),
        "events": siem_entries
    }


def transform_to_text_report(indicators):
    """
    Produce a human-readable text report of final filtered indicators.
    """

    lines = []
    lines.append("=== Threat Intelligence Report ===")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Total Indicators: {len(indicators)}")
    lines.append("")

    for ind in indicators:
        lines.append(f"- ID: {ind['id']}")
        lines.append(f"  Type: {ind['type']}")
        lines.append(f"  Value: {ind['value']}")
        lines.append(f"  Threat Level: {ind['threat_level']}")
        lines.append(f"  Confidence: {ind['confidence']}%")
        lines.append(f"  First Seen: {ind['first_seen']}")
        lines.append(f"  Sources: {', '.join(ind['sources'])}")
        lines.append("")

    return "\n".join(lines)