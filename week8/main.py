# These lines import the functions we previously created in the "core" folder.
# Each function handles one step of the threat‑intelligence pipeline.
from core.loader import load_all_feeds
from core.normalizer import normalize_all
from core.validator import validate_indicators
from core.deduper import deduplicate_indicators
from core.filter import filter_indicators
from core.transform import (
    transform_to_firewall,
    transform_to_siem,
    transform_to_text_report
)
from core.stats import generate_statistics


# =====================================================
# PHASE 3 — LOAD + NORMALIZE
# =====================================================
# This step loads all vendor threat feeds (JSON files)
# and converts them into one consistent, standard format.
raw = load_all_feeds()             # Load raw data from Vendor A/B/C feeds
all_indicators = normalize_all(raw) # Convert all vendors into one standard structure

print(f"\nLoaded + Normalized: {len(all_indicators)} indicators")
print("First normalized indicator:", all_indicators[0])


# =====================================================
# PHASE 4 — VALIDATION
# =====================================================
# This checks each indicator to make sure:
# - Required fields are present
# - Confidence is a number between 0 and 100
# - Type and value are correct
valid_indicators, error_count, error_list = validate_indicators(all_indicators)

print(f"\nValid indicators: {len(valid_indicators)}")
print(f"Validation errors: {error_count}")
if error_count:
    print("Sample error:", error_list[0])


# =====================================================
# PHASE 5 — DEDUPLICATION
# =====================================================
# This finds duplicate indicators coming from multiple vendors.
# We keep the indicator with the highest confidence score,
# and merge ALL vendor names into its “sources” list.
deduped_indicators, duplicates_removed = deduplicate_indicators(valid_indicators)

print(f"\nUnique indicators after dedupe: {len(deduped_indicators)}")
print(f"Duplicates removed: {duplicates_removed}")


# =====================================================
# PHASE 6 — FILTERING
# =====================================================
# This applies policy filters to shrink the results:
# - Only high‑confidence indicators (>= 85%)
# - Only "high" and "critical" threat levels
# - Only IPs and domains (no hashes or URLs)
filtered_indicators = filter_indicators(deduped_indicators)

print(f"\nIndicators after filtering: {len(filtered_indicators)}")
if filtered_indicators:
    print("Example filtered indicator:", filtered_indicators[0])


# =====================================================
# PHASE 7 — TRANSFORMATION
# =====================================================
# Here we produce 3 different output formats:
# 1. Firewall format     → used to block bad IPs/domains
# 2. SIEM format         → used by security tools like Splunk/Sentinel
# 3. Text report         → readable report for humans
firewall_output = transform_to_firewall(filtered_indicators)
siem_output = transform_to_siem(filtered_indicators)
text_report = transform_to_text_report(filtered_indicators)

print("\nFirewall Example:", firewall_output["blocklist"][0])
print("\nSIEM Example:", siem_output["events"][0])
print("\nText Report Preview:")
print("\n".join(text_report.splitlines()[:10]))  # Print first 10 lines of report


# =====================================================
# SAVE OUTPUT FILES
# =====================================================
# These two helper functions save the SIEM and text reports
# so you can open them later outside of Python (like in Notepad).

import json

def save_siem_feed(siem_output, filename="siem_feed.json"):
    """Save the SIEM output to a JSON file (machine-readable)."""
    with open(filename, "w") as f:
        json.dump(siem_output, f, indent=4)
    print(f"\n✅ SIEM feed saved to: {filename}")

def save_text_report(text, filename="summary_report.txt"):
    """Save the human-readable summary report to a .txt file."""
    with open(filename, "w") as f:
        f.write(text)
    print(f"✅ Text report saved to: {filename}")

# Actually save the files
save_siem_feed(siem_output)
save_text_report(text_report)


# =====================================================
# PHASE 8 — STATISTICS
# =====================================================
# This creates summary numbers such as:
# - How many indicators were loaded
# - How many passed validation
# - How many duplicates were removed
# - How many survived filtering
# - Distribution by type (IP, domain, hash, etc.)
# - Distribution by threat level
# - Vendor contribution counts
stats = generate_statistics(
    loaded_count=len(all_indicators),
    valid_list=valid_indicators,
    deduped_list=deduped_indicators,
    filtered_list=filtered_indicators
)

print("\n=== Statistics Summary ===")
for k, v in stats.items():
    print(f"{k}: {v}")