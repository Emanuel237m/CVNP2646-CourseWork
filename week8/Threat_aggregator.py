import json
from datetime import datetime

# -------------------------------------------------------
# FUNCTION: load_feed()
# PURPOSE: Opens a JSON file (a vendor's threat feed) and 
#          loads its contents into Python.
# -------------------------------------------------------
def load_feed(filepath):
    try:
        with open(filepath, "r") as f:
            return json.load(f)   # Convert JSON → Python dictionary/list
    except FileNotFoundError:
        print(f"ERROR: File not found → {filepath}")
    except json.JSONDecodeError:
        print(f"ERROR: JSON parsing failed → {filepath}")
    return None    # Return nothing if something goes wrong


# -------------------------------------------------------
# FUNCTION: normalize_indicator()
# PURPOSE: Vendor feeds use different field names.
#          This converts ALL feeds into ONE standard format.
# -------------------------------------------------------
def normalize_indicator(raw, source_name):
    """
    Example:
    Vendor A might use: "value"
    Vendor B might use: "indicator_value"
    Vendor C might use: "ioc"
    
    We convert ALL of them into:
    "value": <same key for all vendors>
    """

    # Try several possible field names until one works.
    type_val = raw.get("type") or raw.get("indicator_type") or raw.get("category")
    value_val = raw.get("value") or raw.get("indicator_value") or raw.get("ioc")
    confidence_val = raw.get("confidence") or raw.get("score") or raw.get("confidence_score")
    threat_val = raw.get("threat") or raw.get("severity") or raw.get("risk")
    first_seen_val = raw.get("first_seen") or raw.get("seen") or raw.get("first_detected")

    # Vendor A uses "id", Vendor B "uid", Vendor C "ref"
    id_val = raw.get("id") or raw.get("uid") or raw.get("ref")

    # Return a unified (standardized) dictionary for ALL vendors
    return {
        "id": id_val,
        "type": type_val,
        "value": value_val,
        "confidence": confidence_val,
        "threat_level": threat_val,
        "first_seen": first_seen_val,
        "sources": [source_name],   # Track which vendor provided this indicator
    }


# -------------------------------------------------------
# PHASE 3 — LOAD & NORMALIZE ALL FEEDS
# -------------------------------------------------------

all_indicators = []   # This list will store indicators from ALL vendors

# Load Vendor A
feed_a = load_feed("vendor_a.json")
if feed_a and "indicators" in feed_a:
    for item in feed_a["indicators"]:
        all_indicators.append(normalize_indicator(item, "VendorA"))

# Load Vendor B
feed_b = load_feed("vendor_b.json")
if feed_b and "items" in feed_b:
    for item in feed_b["items"]:
        all_indicators.append(normalize_indicator(item, "VendorB"))

# Load Vendor C
feed_c = load_feed("vendor_c.json")
if feed_c and "data" in feed_c:
    for item in feed_c["data"]:
        all_indicators.append(normalize_indicator(item, "VendorC"))

# Show basic information about what was loaded
print(f"Total normalized indicators: {len(all_indicators)}")
print("First normalized indicator:")
print(all_indicators[0])
print("\nLast normalized indicator:")
print(all_indicators[-1])


# -------------------------------------------------------
# FUNCTION: validate_indicators()
# PURPOSE: Ensures indicators contain proper information.
# -------------------------------------------------------
def validate_indicators(indicators):
    """
    Why validate?
    - Sometimes vendor feeds contain mistakes
    - Example: missing 'value' or invalid confidence
    - This function separates GOOD indicators from BAD ones
    """

    valid = []     # List of good indicators
    errors = []    # List of descriptions of bad indicators

    allowed_types = {"ip", "domain", "hash", "url"}

    for idx, ind in enumerate(indicators):

        # Check for missing required fields
        required_fields = ["id", "type", "value", "confidence"]
        missing = [f for f in required_fields if ind.get(f) is None]

        if missing:
            errors.append(f"Indicator {idx}: missing required fields → {missing}")
            continue  # Skip this indicator completely

        # Check valid indicator type
        if ind["type"] not in allowed_types:
            errors.append(f"Indicator {idx}: invalid type '{ind['type']}'")
            continue

        # Check the value field is a non-empty string
        if not isinstance(ind["value"], str) or ind["value"].strip() == "":
            errors.append(f"Indicator {idx}: value is empty or not a string")
            continue

        # Check confidence: must be a number between 0–100
        try:
            conf = float(ind["confidence"])
        except ValueError:
            errors.append(f"Indicator {idx}: confidence not numeric")
            continue

        if not (0 <= conf <= 100):
            errors.append(f"Indicator {idx}: confidence {conf} is out of range 0–100")
            continue

        # Save cleaned confidence value
        ind["confidence"] = conf
        valid.append(ind)

    return valid, len(errors), errors


# Execute Phase 4
valid_indicators, error_count, error_list = validate_indicators(all_indicators)

print(f"\nValid indicators: {len(valid_indicators)}")
print(f"Errors detected: {error_count}")
if error_count:
    print("Example error:", error_list[0])


# -------------------------------------------------------
# PHASE 5 — DEDUPLICATION
# -------------------------------------------------------
def deduplicate_indicators(indicators):
    """
    Rules:
    - Indicators are duplicates if they have SAME type and SAME value.
    - Keep the one with the highest confidence.
    - Merge the vendor source lists.
    """

    unique = {}       # Stores the best version of each indicator
    duplicate_count = 0

    for ind in indicators:
        key = (ind["type"], ind["value"])  # This uniquely identifies an indicator

        if key not in unique:
            unique[key] = ind
        else:
            duplicate_count += 1
            existing = unique[key]

            # Keep the one with the highest confidence score
            if ind["confidence"] > existing["confidence"]:
                ind["sources"].extend(existing["sources"])
                unique[key] = ind
            else:
                existing["sources"].extend(ind["sources"])

    return list(unique.values()), duplicate_count


# Execute Phase 5
deduped_indicators, duplicates_removed = deduplicate_indicators(valid_indicators)

print(f"\nUnique indicators after deduplication: {len(deduped_indicators)}")
print(f"Duplicates removed: {duplicates_removed}")


# -------------------------------------------------------
# PHASE 6 — FILTERING
# -------------------------------------------------------
def filter_indicators(indicators, min_conf=85, levels=None, types=None):
    """
    Filtering rules:
    - Only keep indicators with confidence >= 85
    - Only keep "high" or "critical" threat level
    - Only keep IP and domain indicators
    """

    if levels is None:
        levels = ["high", "critical"]

    if types is None:
        types = ["ip", "domain"]

    filtered = [
        ind for ind in indicators
        if ind["confidence"] >= min_conf
        and ind["threat_level"] in levels
        and ind["type"] in types
    ]

    return filtered


# Execute Phase 6
filtered_indicators = filter_indicators(deduped_indicators)

print(f"\nIndicators after filtering: {len(filtered_indicators)}")
print("Example filtered indicator:")
if filtered_indicators:
    print(filtered_indicators[0])


# -------------------------------------------------------
# PHASE 7 — TRANSFORMATION (Output Formatting)
# -------------------------------------------------------
def transform_to_firewall(indicators):
    """
    Creates a blocklist format used by firewalls.
    Example:
    {
      "address": "203.0.113.10",
      "action": "block",
      ...
    }
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
    Creates a SIEM-friendly JSON structure.
    SIEM tools like Splunk, Sentinel, QRadar use this format.
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
    Creates a clean, readable text report for humans.
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


# Execute Phase 7
firewall_output = transform_to_firewall(filtered_indicators)
siem_output = transform_to_siem(filtered_indicators)
text_report = transform_to_text_report(filtered_indicators)

print("\nFirewall format example:")
print(firewall_output["blocklist"][0])

print("\nSIEM format example:")
print(siem_output["events"][0])

print("\nText report preview:")
print(text_report.splitlines()[0:10])  # shows first 10 lines



from collections import Counter

# -------------------------------------------------------
# PHASE 8 — STATISTICS
# -------------------------------------------------------
def generate_statistics(loaded_count, valid_list, deduped_list, filtered_list):
    """
    Generates numbers that summarize:
    - How many items loaded
    - How many were valid
    - How many survived dedupe + filtering
    - Type breakdown
    - Threat level breakdown
    - Vendor contributions
    """

    type_counts = Counter(ind["type"] for ind in filtered_list)
    severity_counts = Counter(ind["threat_level"] for ind in filtered_list)

    source_counts = Counter()
    for ind in deduped_list:
        for src in ind["sources"]:
            source_counts[src] += 1

    stats = {
        "total_loaded": loaded_count,
        "valid_count": len(valid_list),
        "unique_after_dedup": len(deduped_list),
        "filtered_count": len(filtered_list),
        "duplicates_removed": loaded_count - len(deduped_list),
        "type_distribution": dict(type_counts),
        "threat_distribution": dict(severity_counts),
        "source_contribution": dict(source_counts),
    }

    return stats


# Execute Phase 8
stats = generate_statistics(
    loaded_count=len(all_indicators),
    valid_list=valid_indicators,
    deduped_list=deduped_indicators,
    filtered_list=filtered_indicators
)

print("\n=== Statistics Summary ===")
for key, value in stats.items():
    print(f"{key}: {value}")