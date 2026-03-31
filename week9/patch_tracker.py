import json   # The built‑in JSON library allows Python to read JSON files.
from datetime import datetime   # Needed for working with dates and time

# ======================================================================
# STAGE 1 — LOAD INVENTORY FROM JSON
# ======================================================================

def load_inventory(filepath):
    """
    Load the host inventory JSON file into Python.

    -------------------------------------------------------------------------
    PURPOSE:
        This function reads a JSON file that contains your organization's
        20‑host system inventory. The JSON file is expected to contain a LIST
        of HOST RECORDS, where each record is a dictionary describing one host
        (hostname, OS, last patch date, tags, etc.).

    WHY THIS IS IMPORTANT:
        The entire patch tracking system depends on loading this dataset first.
        Every other step—calculating patch age, scoring risk, generating
        reports—requires this inventory to be available in memory as Python
        dictionaries.

    PARAMETERS:
        filepath (str):
            A string representing the path to the JSON file. In your project
            structure, this will usually be "host_inventory.json".

    RETURNS:
        list:
            A list of host dictionaries loaded from the JSON file.

    ERROR HANDLING:
        - FileNotFoundError → File missing  
        - JSONDecodeError  → Invalid JSON syntax  
    -------------------------------------------------------------------------
    """
    try:
        with open(filepath, "r") as f:
            data = json.load(f)

            if isinstance(data, list):
                return data   # ✅ Success

            else:
                print("ERROR: JSON file must contain a list of host records.")
                return []

    except FileNotFoundError:
        print(f"ERROR: File not found → {filepath}")
        return []

    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON format in → {filepath}")
        return []


# ======================================================================
# STAGE 2 — CALCULATE DAYS SINCE PATCH
# ======================================================================

def calculate_days_since_patch(host):
    """
    Calculate how many days have passed since the host was last patched.

    -------------------------------------------------------------------------
    PURPOSE:
        Extracts host["last_patch_date"], converts it into a datetime object,
        compares it to today's date, and stores the number of days as a new
        field: host["days_since_patch"].

    WHY THIS MATTERS:
        Patch age is a major factor in risk scoring. Older patches = higher risk.

    RETURNS:
        int — The number of days since last patch (or -1 if invalid).
    -------------------------------------------------------------------------
    """

    date_string = host.get("last_patch_date")

    if not date_string:
        print(f"WARNING: Host {host.get('hostname')} has no last_patch_date!")
        host["days_since_patch"] = -1
        return -1

    try:
        last_patch_date = datetime.strptime(date_string, "%Y-%m-%d")
        delta = datetime.now() - last_patch_date
        days_since_patch = delta.days

        host["days_since_patch"] = days_since_patch
        return days_since_patch

    except ValueError:
        print(f"ERROR: Invalid date format for host {host.get('hostname')}: {date_string}")
        host["days_since_patch"] = -1
        return -1


# ======================================================================
# STAGE 3 — FILTERING FUNCTIONS
# ======================================================================

def filter_by_os(hosts, os_type):
    """
    Filter hosts by operating system (case-insensitive partial match).

    Example:
        filter_by_os(hosts, "windows")
        filter_by_os(hosts, "linux")
    """
    os_type = os_type.lower()
    return [host for host in hosts if os_type in host.get("os", "").lower()]


def filter_by_criticality(hosts, level):
    """
    Filter hosts by criticality level.
    Levels: critical, high, medium, low
    """
    return [
        host for host in hosts
        if host.get("criticality", "").lower() == level.lower()
    ]


def filter_by_environment(hosts, env):
    """
    Filter hosts by environment.
    Environments: production, staging, development
    """
    return [
        host for host in hosts
        if host.get("environment", "").lower() == env.lower()
    ]


def filter_critical_production(hosts):
    """
    Filter hosts that are BOTH:
        critical AND production

    These are the organization's highest-priority, highest-risk systems.
    """
    return [
        host for host in hosts
        if host.get("criticality", "").lower() == "critical"
        and host.get("environment", "").lower() == "production"
    ]


# ======================================================================
# STAGE 4 — RISK SCORING
# ======================================================================

def calculate_risk_score(host):
    """
    Calculate risk score for a single host (0-100 scale).

    FACTORS:
        • Criticality: critical/high/medium/low
        • Patch age: >90 / >60 / >30
        • Environment: production/staging/development
        • Tags: pci-scope, hipaa, internet-facing

    Adds host["risk_score"]
    """

    score = 0

    # --- Criticality ---
    crit = host.get("criticality", "").lower()
    if crit == "critical": score += 40
    elif crit == "high": score += 25
    elif crit == "medium": score += 10
    elif crit == "low": score += 5

    # --- Patch Age ---
    days = host.get("days_since_patch", 0)
    if days > 90: score += 30
    elif days > 60: score += 20
    elif days > 30: score += 10

    # --- Environment ---
    env = host.get("environment", "").lower()
    if env == "production": score += 15
    elif env == "staging": score += 8
    elif env == "development": score += 3

    # --- Tags ---
    tags = host.get("tags", [])
    if "pci-scope" in tags: score += 10
    if "hipaa" in tags: score += 10
    if "internet-facing" in tags: score += 15

    score = min(score, 100)
    host["risk_score"] = score
    return score


def get_risk_level(score):
    """
    Convert numeric score → risk level.
    """
    if score >= 70: return "critical"
    elif score >= 50: return "high"
    elif score >= 25: return "medium"
    else: return "low"


# ======================================================================
# STAGE 5 — HIGH-RISK HOST IDENTIFICATION
# ======================================================================

def get_high_risk_hosts(hosts, threshold=50):
    """
    Return hosts whose risk_score >= threshold.

    Requirements:
        - Default threshold = 50 (high risk)
        - Sort descending by risk_score
    """
    high = [
        host for host in hosts
        if host.get("risk_score", 0) >= threshold
    ]

    return sorted(high, key=lambda h: h["risk_score"], reverse=True)


# ======================================================================
# STAGE 6 — JSON REPORT GENERATION
# ======================================================================

def generate_json_report(hosts, high_risk_hosts, filename="high_risk_report.json"):
    """
    Generate JSON report used for automation / SIEM ingestion.
    Includes:
        - Report timestamp (ISO)
        - Risk distribution counts
        - High-risk host list
    """

    report_time = datetime.now().isoformat()

    # Distribution counts
    distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for host in hosts:
# ===== STAGE 7 TEST =====
        print("\n--- Stage 7 Test: Text Summary Report ---")

# Load inventory
hosts = load_inventory("host_inventory.json")

# Run Stage 2 + Stage 4 processing
for h in hosts:
    calculate_days_since_patch(h)
    calculate_risk_score(h)
    h["risk_level"] = get_risk_level(h["risk_score"])

# Identify high-risk systems (Stage 5)
high_risk_hosts = get_high_risk_hosts(hosts, threshold=50)

# Generate the text summary (Stage 7)
def generate_text_summary(hosts, high_risk_hosts):
    pass

generate_text_summary(hosts, high_risk_hosts)

print("✅ Check your folder for 'patch_summary.txt'")
def generate_html_report(hosts, filename="patch_report.html"):
    """
    Generate a simple, color‑coded HTML report showing the full patch
    compliance inventory.

    -------------------------------------------------------------------------
    PURPOSE:
        This function creates a clean and readable HTML page that displays
        all hosts in a tabular format. Unlike the sortable version, this is
        a SIMPLE static HTML table with:
            • Color‑coded rows based on risk level
            • Clear column headers
            • No JavaScript, no sorting arrows, no dynamic behavior

        This version is ideal for:
            - Submitting to management
            - Emailing as a static report
            - Uploading to an LMS
            - Use cases where JavaScript is discouraged

    COLOR CODING:
        critical  → bright red
        high      → orange
        medium    → yellow/gold
        low       → light green

    PARAMETERS:
        hosts (list):
            The full list of enriched host dictionaries. Each host MUST have:
                - risk_score
                - risk_level
                - days_since_patch
                - criticality
                - environment
                - tags

        filename (str):
            Name of the output HTML file. Default = "patch_report.html".

    RETURNS:
        None — writes a fully formatted HTML document to disk.
    -------------------------------------------------------------------------
    """

    # ==============================
    # Inline CSS for table + colors
    # ==============================
    styles = """
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        h2 {
            text-align: center;
            margin-bottom: 5px;
        }
        p {
            text-align: center;
            color: #444;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #444;
            text-align: left;
        }
        th {
            background-color: #222;
            color: white;
        }
        /* Row color coding by risk level */
        .critical { background-color: #ff4c4c; }
        .high { background-color: #ffa64d; }
        .medium { background-color: #ffeb99; }
        .low { background-color: #b3ffb3; }
    </style>
    """

    # ==============================
    # Build HTML document structure
    # ==============================
    html = []
    html.append("<html>")
    html.append("<head>")
    html.append("<title>Patch Compliance Report</title>")
    html.append(styles)   # inject CSS
    html.append("</head>")
    html.append("<body>")

    # Report heading + timestamp
    html.append("<h2>Patch Compliance & Risk Assessment Report</h2>")
    html.append(f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")

    # ==============================
    # Table header (static)
    # ==============================
    html.append("<table>")
    html.append("""
        <tr>
            <th>Hostname</th>
            <th>IP Address</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
            <th>Days Since Patch</th>
            <th>Criticality</th>
            <th>Environment</th>
            <th>Tags</th>
        </tr>
    """)

    # ==============================
    # Table rows generated per host
    # ==============================
    for host in hosts:
        # Determine CSS class based on risk level
        row_class = host.get("risk_level", "low").lower()

        html.append(f"""
        <tr class="{row_class}">
            <td>{host.get('hostname')}</td>
            <td>{host.get('ip_address')}</td>
            <td>{host.get('risk_score')}</td>
            <td>{host.get('risk_level')}</td>
            <td>{host.get('days_since_patch')}</td>
            <td>{host.get('criticality')}</td>
            <td>{host.get('environment')}</td>
            <td>{", ".join(host.get("tags", []))}</td>
        </tr>
        """)

    # Close table + HTML
    html.append("</table>")
    html.append("</body>")
    html.append("</html>")

    # ==============================
    # Write HTML file to disk
    # ==============================
    with open(filename, "w") as f:
        f.write("\n".join(html))

    print(f"✅ HTML Report generated → {filename}")
# ======================================================================
# STAGE 9 — MAIN EXECUTION PIPELINE
# ======================================================================

if __name__ == "__main__":
    print("\n=== Patch Compliance Tracker — Starting Analysis ===")

    # 1. Load host inventory (Stage 1)
    hosts = load_inventory("host_inventory.json")
    if not hosts:
        print("ERROR: No hosts loaded. Exiting.")
        exit()

    # 2. Calculate days since patch + risk score + risk level
    for host in hosts:
        calculate_days_since_patch(host)          # Stage 2
        calculate_risk_score(host)                # Stage 4
        host["risk_level"] = get_risk_level(host["risk_score"])

    # 3. Identify high-risk systems (Stage 5)
    high_risk_hosts = get_high_risk_hosts(hosts, threshold=50)

    # 4. Generate all reports (Stages 6–8)
    generate_json_report(hosts, high_risk_hosts)      # JSON
    generate_text_summary(hosts, high_risk_hosts)     # TXT
    generate_html_report(hosts)                       # HTML

    # 5. Final confirmation
    print("\n✅ All reports generated successfully!")
    print("   → high_risk_report.json")
    print("   → patch_summary.txt")
    print("   → patch_report.html")
    print("\n=== Patch Compliance Tracker — Completed ===\n")   