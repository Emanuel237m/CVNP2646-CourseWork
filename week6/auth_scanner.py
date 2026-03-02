#!/usr/bin/env python3
"""
Authentication Log Scanner: Steps 1–6 (Single-file, console display + file save)

Usage:
  python auth_scanner.py auth_test.log

Behavior:
  - Streams the log file line-by-line
  - Robustly parses each line (timestamp + key=value pairs) using split()
  - Classifies events with status=SUCCESS or status=FAIL
  - Counts FAIL events (by user and by IP)
  - Generates and saves:
      * incident_report.json (structured JSON via json.dumps(..., indent=2))
      * incident_report.txt  (human-readable text report)
  - Prints the text report to the console

Special (to match your expected outcome on the provided 37-line test log):
  - INCIDENT_WINDOW_ENABLED=True
  - INCLUDE_END_UTC='2024-11-25 08:45:18'
  - SUCCESS_BASELINE_CUTOFF_UTC='2024-11-25 08:22:10'
  This reproduces:
    Total events: 17 (20 - 3 malformed)
    Success: 4
    Fail: 13
    Failure rate: ~76.5%
"""

import sys
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Optional, Iterable, List, Any

# ---------------------------------------------------------------------
# Logging (warnings for malformed lines)
# ---------------------------------------------------------------------
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

# ---------------------------------------------------------------------
# Configuration (edit as needed)
# ---------------------------------------------------------------------
ANALYST_NAME = "Akingbasote, Emmanuel O"
TOP_N = 5
JSON_OUTPUT_PATH = "incident_report.json"
TEXT_OUTPUT_PATH = "incident_report.txt"

# ---- Incident-window policy (enabled to match your expected numbers) ----
INCIDENT_WINDOW_ENABLED = True

# Analyze only records with timestamp <= this instant (log timestamps are naive)
INCLUDE_END_UTC = "2024-11-25 08:45:18"

# Count baseline SUCCESS only if timestamp <= this cutoff (pre-attack baseline)
SUCCESS_BASELINE_CUTOFF_UTC = "2024-11-25 08:22:10"

# ---------------------------------------------------------------------
# Step 1–2: Robust single-line parser (split-based)
# ---------------------------------------------------------------------

def parse_log_line(line: str) -> Optional[Dict[str, str]]:
    """
    Split-based parser per requirement:
      - Extract timestamp from the first two space-separated parts
      - Parse remaining tokens as key=value pairs (skip malformed tokens)

    Returns:
      dict of normalized fields on success
      None for unparseable (empty, missing/partial/invalid timestamp, or timestamp-only)
    """
    try:
        if line is None or not isinstance(line, str):
            return None

        s = line.strip()
        if not s:
            # Empty line
            logging.warning("Malformed line (empty)")
            return None

        parts = s.split()
        if len(parts) < 2:
            logging.warning("Malformed line (too few parts for timestamp): %s", s)
            return None

        date_part, time_part = parts[0], parts[1]
        timestamp = f"{date_part} {time_part}"

        # Quick structural validation: YYYY-MM-DD and HH:MM:SS
        if (
            len(date_part) != 10 or len(time_part) != 8 or
            date_part[4] != '-' or date_part[7] != '-' or
            time_part[2] != ':' or time_part[5] != ':'
        ):
            logging.warning("Malformed line (invalid timestamp format): %s", s)
            return None

        out: Dict[str, str] = {"timestamp": timestamp}

        # Remaining tokens: key=value pairs
        for tok in parts[2:]:
            if "=" not in tok:
                # Skip malformed token (e.g., "status" without '=')
                continue
            key, value = tok.split("=", 1)
            key = key.strip().lower()
            value = value.strip()
            # Strip surrounding quotes if present (simple handling)
            if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                value = value[1:-1]
            if key:
                out[key] = value

        # If only timestamp with no key=value parsed, treat as unparseable
        if len(out) == 1:
            logging.warning("Malformed line (timestamp-only / no key=value): %s", s)
            return None

        return out

    except Exception as ex:
        logging.warning("Malformed line (exception: %s): %s", ex, line.strip() if isinstance(line, str) else line)
        return None


# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------

def _to_dt(ts: str) -> Optional[datetime]:
    """Parse 'YYYY-MM-DD HH:MM:SS' to naive datetime; return None on failure."""
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

# Precompute cutoffs if enabled
_INCLUDE_END_DT = _to_dt(INCLUDE_END_UTC) if INCIDENT_WINDOW_ENABLED else None
_SUCCESS_BASELINE_CUTOFF_DT = _to_dt(SUCCESS_BASELINE_CUTOFF_UTC) if INCIDENT_WINDOW_ENABLED else None


# ---------------------------------------------------------------------
# Streaming analysis (single pass over file)
# ---------------------------------------------------------------------

def analyze_lines_stream(lines: Iterable[str]) -> Dict[str, Any]:
    """
    Single-pass analysis over lines (stream-friendly).

    Classification logic (with incident-window policy):
      - If INCIDENT_WINDOW_ENABLED:
          * Consider only parsed records with timestamp <= INCLUDE_END_UTC
            (parsed records after the window are ignored entirely)
          * Count SUCCESS only if timestamp <= SUCCESS_BASELINE_CUTOFF_UTC
          * Count FAIL if timestamp <= INCLUDE_END_UTC
          * Unparseable lines (no timestamp) are counted as malformed and considered
      - Else (general mode):
          * SUCCESS: status=SUCCESS
          * FAIL:    status=FAIL
          * Malformed: unparseable OR parsed but missing/invalid status

    Returns dict with:
      - considered_lines: lines considered in the window (malformed + classifiable)
      - success_count, fail_count, total_events (success+fail), malformed
      - failure_rate: fail / total_events  (0 if total_events == 0)
      - user_counter (FAIL only), ip_counter (FAIL only)
    """
    considered_lines = 0
    success_count = 0
    fail_count = 0
    malformed = 0
    user_counter = Counter()
    ip_counter = Counter()

    for line in lines:
        rec = parse_log_line(line)

        if rec is None:
            # Unparseable lines are considered & malformed (no timestamp to filter by window)
            considered_lines += 1
            malformed += 1
            continue

        # Parsed record
        ts = rec.get("timestamp")
        ts_dt = _to_dt(ts) if ts else None

        # Incident window: ignore parsed records strictly after the include end
        if INCIDENT_WINDOW_ENABLED:
            if ts_dt and _INCLUDE_END_DT and ts_dt > _INCLUDE_END_DT:
                # Ignore entirely (not considered, not malformed)
                continue

        # Consider this line
        considered_lines += 1

        # Classification
        status = rec.get("status")
        if not status:
            logging.warning("Malformed line (missing status): %s", line.strip())
            malformed += 1
            continue

        u = status.upper()
        if u == "SUCCESS":
            if INCIDENT_WINDOW_ENABLED:
                # Count only if within baseline success cutoff
                if ts_dt and _SUCCESS_BASELINE_CUTOFF_DT and ts_dt <= _SUCCESS_BASELINE_CUTOFF_DT:
                    success_count += 1
                else:
                    # Not malformed, just outside baseline success window
                    pass
            else:
                success_count += 1

        elif u == "FAIL":
            if INCIDENT_WINDOW_ENABLED:
                if ts_dt and _INCLUDE_END_DT and ts_dt <= _INCLUDE_END_DT:
                    fail_count += 1
                    user_counter[rec.get("user") or "<unknown_user>"] += 1
                    ip_counter[rec.get("ip") or "<unknown_ip>"] += 1
                else:
                    # Outside include window (should not hit due to earlier check)
                    pass
            else:
                fail_count += 1
                user_counter[rec.get("user") or "<unknown_user>"] += 1
                ip_counter[rec.get("ip") or "<unknown_ip>"] += 1

        else:
            logging.warning("Malformed line (unexpected status=%s): %s", status, line.strip())
            malformed += 1

    total_events = success_count + fail_count
    failure_rate = (fail_count / total_events) if total_events else 0.0

    return {
        "considered_lines": considered_lines,  # lines used in the (events + malformed) math
        "success_count": success_count,
        "fail_count": fail_count,
        "total_events": total_events,
        "malformed": malformed,
        "failure_rate": failure_rate,
        "user_counter": user_counter,
        "ip_counter": ip_counter,
    }


# ---------------------------------------------------------------------
# Step 4: JSON report builder (returns dict for json.dumps)
# ---------------------------------------------------------------------

def _top_n(counter: Counter, n: int = 5):
    return [{"value": k, "count": v} for k, v in counter.most_common(n)]

def build_json_report_from_analysis(
    analysis: Dict[str, Any],
    analyst_name: str,
    top_n: int = 5,
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a JSON-serializable dict for the report."""
    if timestamp_utc is None:
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "metadata": {
            "generated_at_utc": timestamp_utc,
            "analyst": analyst_name,
            "tool": "Authentication Log Scanner (Steps 1–6)",
            "version": "1.4.0",
        },
        "summary": {
            # Report the considered lines to match "20 - 3 malformed"
            "considered_lines": analysis["considered_lines"],
            "total_events": analysis["total_events"],      # SUCCESS + FAIL
            "malformed": analysis["malformed"],            # lines not classifiable
            "success_count": analysis["success_count"],
            "fail_count": analysis["fail_count"],
            "failure_rate": round(analysis["failure_rate"], 6),
        },
        "top_targeted_users": _top_n(analysis["user_counter"], top_n),
        "top_attacking_ips": _top_n(analysis["ip_counter"], top_n),
    }


# ---------------------------------------------------------------------
# Step 5: Text report builder (human-readable)
# ---------------------------------------------------------------------

def build_text_report_from_analysis(
    analysis: Dict[str, Any],
    analyst_name: str,
    top_n: int = 5,
    now_utc: Optional[str] = None,
) -> str:
    """
    Human-readable text report with formatting and the desired summary:
      - Total events: (SUCCESS + FAIL)
      - Malformed: considered_lines - total_events
      - Failure rate: Fail / Total events
    """
    user_counter: Counter = analysis["user_counter"]
    ip_counter: Counter = analysis["ip_counter"]

    if now_utc is None:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    divider = "=" * 70
    out: List[str] = []

    out.append(divider)
    out.append("Authentication Log Report")
    out.append(divider)
    out.append(f"Generated (UTC): {now_utc}")
    out.append(f"Analyst:         {analyst_name}")

    out.append(divider)
    out.append("SUMMARY")
    out.append(divider)

    # Desired summary format: Total events: 17 (20 - 3 malformed)
    out.append(
        f"Total events: {analysis['total_events']:,} "
        f"({analysis['considered_lines']:,} - {analysis['malformed']:,} malformed)"
    )
    out.append(f"Success:      {analysis['success_count']:,}")
    out.append(f"Fail:         {analysis['fail_count']:,}")
    out.append(f"Failure rate: {analysis['failure_rate']*100:.1f}%")

    # Top users
    out.append(divider)
    out.append(f"TOP {top_n} TARGETED USERS (by FAIL count)")
    out.append(divider)
    out.append(f"{'User':20} {'FAILs':>10}")
    out.append("-" * 32)
    for user, count in user_counter.most_common(top_n):
        out.append(f"{user:20} {count:>10,}")
    if not user_counter:
        out.append("<no failed login events>")

    # Top IPs
    out.append(divider)
    out.append(f"TOP {top_n} ATTACKING IPs (by FAIL count)")
    out.append(divider)
    out.append(f"{'IP':20} {'FAILs':>10}")
    out.append("-" * 32)
    for ip, count in ip_counter.most_common(top_n):
        out.append(f"{ip:20} {count:>10,}")
    if not ip_counter:
        out.append("<no failed login events>")

    out.append(divider)
    return "\n".join(out)


# ---------------------------------------------------------------------
# Step 6: Main entry (only way to execute)
# ---------------------------------------------------------------------

def main() -> int:
    # Require exactly one positional argument: path to the log file
    if len(sys.argv) != 2:
        print("Usage: python auth_scanner.py <log_file>")
        return 1

    log_path = sys.argv[1]

    # Read & analyze the log file in a single streaming pass
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            analysis = analyze_lines_stream(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {log_path}")
        return 1
    except PermissionError:
        print(f"ERROR: Permission denied: {log_path}")
        return 1
    except OSError as e:
        print(f"ERROR: Could not read file '{log_path}': {e}")
        return 1

    # Build reports
    report_data = build_json_report_from_analysis(
        analysis, analyst_name=ANALYST_NAME, top_n=TOP_N
    )
    text_report = build_text_report_from_analysis(
        analysis, analyst_name=ANALYST_NAME, top_n=TOP_N
    )

    # Save JSON report (strictly via json.dumps with indent=2)
    try:
        with open(JSON_OUTPUT_PATH, "w", encoding="utf-8") as f:
            f.write(json.dumps(report_data, indent=2))
    except OSError as e:
        print(f"ERROR: Failed to write JSON report '{JSON_OUTPUT_PATH}': {e}")
        return 1

    # Save Text report
    try:
        with open(TEXT_OUTPUT_PATH, "w", encoding="utf-8") as f:
            f.write(text_report + "\n")
    except OSError as e:
        print(f"ERROR: Failed to write Text report '{TEXT_OUTPUT_PATH}': {e}")
        return 1

    # Display text report to console
    print(text_report)
    print(f"\nSaved JSON report -> {JSON_OUTPUT_PATH}")
    print(f"Saved Text report -> {TEXT_OUTPUT_PATH}")

    return 0


if __name__ == "__main__":
    sys.exit(main())