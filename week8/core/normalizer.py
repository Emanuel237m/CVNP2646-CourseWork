# core/normalizer.py

def normalize_indicator(raw, source_name):
    """Convert vendor-specific formats into a unified standard structure."""

    type_val = (
        raw.get("type") or
        raw.get("indicator_type") or
        raw.get("category")
    )

    value_val = (
        raw.get("value") or
        raw.get("indicator_value") or
        raw.get("ioc")
    )

    confidence_val = (
        raw.get("confidence") or
        raw.get("score") or
        raw.get("confidence_score")
    )

    threat_val = (
        raw.get("threat") or
        raw.get("severity") or
        raw.get("risk")
    )

    first_seen_val = (
        raw.get("first_seen") or
        raw.get("seen") or
        raw.get("first_detected")
    )

    id_val = (
        raw.get("id") or
        raw.get("uid") or
        raw.get("ref")
    )

    return {
        "id": id_val,
        "type": type_val,
        "value": value_val,
        "confidence": confidence_val,
        "threat_level": threat_val,
        "first_seen": first_seen_val,
        "sources": [source_name],
    }


def normalize_all(raw_list):
    """
    Convert a list of (raw_indicator, vendor_name) tuples
    into a list of normalized indicator dictionaries.
    """

    normalized = []
    for raw, vendor in raw_list:
        normalized.append(normalize_indicator(raw, vendor))

    return normalized