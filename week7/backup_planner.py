import json
import sys
import random
from pathlib import Path
from datetime import datetime


# =====================================================================
# PART 1 — JSON STRUCTURE (Implemented implicitly)
# The configuration is expected to match this structure:
#
# {
#   "plan_name": "...",
#   "version": "...",
#   "created_by": "...",
#   "description": "...",
#
#   "sources": [
#       {
#         "name": "...",
#         "path": "...",
#         "recursive": true,
#         "include_patterns": [...],
#         "exclude_patterns": [...]
#       }
#   ],
#
#   "destination": {
#       "base_path": "...",
#       "create_timestamped_folders": true,
#       "retention_days": 90
#   },
#
#   "options": {
#       "verify_backups": true,
#       "max_file_size_mb": 100
#   }
# }
# =====================================================================



# =====================================================================
# PART 2 — VALIDATION SYSTEM
# =====================================================================
def validate_config(config):
    """
    Validate backup configuration according to 4-level validation rules.
    Returns:
        (is_valid: bool, errors: list)
    """

    errors = []

    # -------------------------------------------------------------
    # LEVEL 1 — STRUCTURE VALIDATION
    # -------------------------------------------------------------
    if config is None:
        errors.append("Configuration object is None.")
        return False, errors

    if not isinstance(config, dict):
        errors.append("Configuration must be a JSON object (dict).")
        return False, errors

    # -------------------------------------------------------------
    # LEVEL 2 — REQUIRED FIELDS
    # -------------------------------------------------------------
    required = ["plan_name", "version", "created_by", "sources", "destination"]

    for field in required:
        if field not in config:
            errors.append(f"Missing required field: '{field}'")

    sources = config.get("sources")
    destination = config.get("destination")

    # -------------------------------------------------------------
    # LEVEL 3 — TYPE VALIDATION
    # -------------------------------------------------------------
    if "plan_name" in config and not isinstance(config["plan_name"], str):
        errors.append("'plan_name' must be a string")

    if "version" in config and not isinstance(config["version"], str):
        errors.append("'version' must be a string")

    if "created_by" in config and not isinstance(config["created_by"], str):
        errors.append("'created_by' must be a string")

    if "sources" in config and not isinstance(sources, list):
        errors.append(f"'sources' must be a list, got {type(sources).__name__}")

    if "destination" in config and not isinstance(destination, dict):
        errors.append(f"'destination' must be a dictionary, got {type(destination).__name__}")

    if "options" in config and not isinstance(config["options"], dict):
        errors.append(f"'options' must be a dictionary, got {type(config['options']).__name__}")

    # -------------------------------------------------------------
    # LEVEL 4 — VALUE VALIDATION
    # -------------------------------------------------------------
    # Validate sources list contents
    if isinstance(sources, list):
        if len(sources) == 0:
            errors.append("Sources list cannot be empty.")

        for i, src in enumerate(sources):
            if not isinstance(src, dict):
                errors.append(f"Source {i}: must be an object")
                continue

            if "name" not in src:
                errors.append(f"Source {i}: missing 'name' field")

            if "path" not in src:
                errors.append(f"Source {i}: missing 'path' field")
            else:
                if not isinstance(src["path"], str) or src["path"].strip() == "":
                    errors.append(f"Source {i}: 'path' cannot be empty")

            if "include_patterns" in src and not isinstance(src["include_patterns"], list):
                errors.append(f"Source {i}: 'include_patterns' must be a list")

            if "exclude_patterns" in src and not isinstance(src["exclude_patterns"], list):
                errors.append(f"Source {i}: 'exclude_patterns' must be a list")

            if "recursive" in src and not isinstance(src["recursive"], bool):
                errors.append(f"Source {i}: 'recursive' must be a boolean")

    # Validate destination
    if isinstance(destination, dict):
        if "base_path" not in destination:
            errors.append("Destination: missing 'base_path' field")
        else:
            if not isinstance(destination["base_path"], str) or destination["base_path"].strip() == "":
                errors.append("Destination: 'base_path' cannot be empty")

        if "create_timestamped_folders" in destination:
            if not isinstance(destination["create_timestamped_folders"], bool):
                errors.append("Destination: 'create_timestamped_folders' must be a boolean")

        if "retention_days" in destination and not isinstance(destination["retention_days"], (int, float)):
            errors.append("Destination: 'retention_days' must be a number")

    # Validate options
    if "options" in config:
        opt = config["options"]

        if "verify_backups" in opt and not isinstance(opt["verify_backups"], bool):
            errors.append("'verify_backups' must be a boolean")

        if "max_file_size_mb" in opt and not isinstance(opt["max_file_size_mb"], (int, float)):
            errors.append("'max_file_size_mb' must be a number")

    # -------------------------------------------------------------
    # FINAL RETURN
    # -------------------------------------------------------------
    return len(errors) == 0, errors



# =====================================================================
# PART 3 — LOAD CONFIG
# =====================================================================
def load_config(filepath):
    """
    Load and parse JSON configuration file.
    Returns dict or None.
    """
    try:
        path = Path(filepath)

        if not path.exists():
            print(f"ERROR: Configuration file not found: {filepath}")
            return None

        with open(path, "r") as f:
            return json.load(f)

    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON: {e}")
        return None

    except Exception as e:
        print(f"ERROR: Unexpected error loading config: {e}")
        return None



# =====================================================================
# PART 4 — DRY-RUN SIMULATION
# =====================================================================
def simulate_backup(config):
    """
    Perform a DRY-RUN backup simulation.
    Generates fake files based on patterns.
    """

    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    destination_base = config["destination"]["base_path"]

    dest_folder = (
        f"{destination_base}/{datetime.now().strftime('%Y-%m-%d_%H%M%S')}"
        if config["destination"].get("create_timestamped_folders", False)
        else destination_base
    )

    operations = []
    total_files = 0
    total_size_mb = 0.0

    for source in config["sources"]:
        source_name = source["name"]
        source_path = source["path"]
        include_patterns = source.get("include_patterns", [])

        file_count = random.randint(5, 15)
        fake_files = []

        for _ in range(file_count):
            pattern = random.choice(include_patterns) if include_patterns else "*.dat"

            if pattern.startswith("*."):
                ext = pattern.replace("*", "")
                fake_name = (
                    f"{source_name.lower().replace(' ', '_')}_"
                    f"{random.randint(1000,9999)}{ext}"
                )
            else:
                fake_name = pattern

            size_mb = round(random.uniform(1.0, 100.0), 1)

            fake_files.append({
                "name": fake_name,
                "size_mb": size_mb
            })

            total_files += 1
            total_size_mb += size_mb

        operations.append({
            "source_name": source_name,
            "source_path": source_path,
            "files": fake_files
        })

    return {
        "plan_name": config["plan_name"],
        "mode": "DRY-RUN",
        "timestamp": timestamp,
        "summary": {
            "total_sources": len(config["sources"]),
            "total_files": total_files,
            "total_size_mb": round(total_size_mb, 2)
        },
        "destination_preview": dest_folder,
        "operations": operations
    }



# =====================================================================
# PART 5 — HUMAN-READABLE REPORT
# =====================================================================
def generate_report(simulation_data):
    """
    Create a human-readable formatted report from simulation data.
    """
    if simulation_data is None:
        return "ERROR: No simulation data available."

    lines = []
    add = lines.append

    add("=" * 70)
    add("              BACKUP PLAN DRY-RUN SIMULATION")
    add("=" * 70)

    add(f"Plan: {simulation_data['plan_name']}")
    add(f"Mode: {simulation_data['mode']}")
    add(f"Timestamp: {simulation_data['timestamp']}")
    add("")

    add("-" * 70)
    add("SUMMARY STATISTICS")
    add("-" * 70)

    summary = simulation_data["summary"]
    add(f"Total Sources:     {summary['total_sources']}")
    add(f"Total Files:       {summary['total_files']}")
    add(f"Total Size:        {summary['total_size_mb']} MB")
    add(f"Destination:       {simulation_data['destination_preview']}")
    add("")

    for idx, op in enumerate(simulation_data["operations"], start=1):
        add("-" * 70)
        add(f"SOURCE {idx}: {op['source_name']}")
        add("-" * 70)

        add(f"Path: {op['source_path']}")
        add(f"Files Found: {len(op['files'])}")
        add("")

        add("Sample Files:")
        sample_count = min(3, len(op["files"]))
        for f in op["files"][:sample_count]:
            add(f"  → {f['name']} ({f['size_mb']} MB)")

        remaining = len(op["files"]) - sample_count
        if remaining > 0:
            add(f"  ... and {remaining} more files")

        add("")

    add("=" * 70)
    add("This was a DRY-RUN simulation. No files were copied.")
    add("To execute actual backup, run with --execute flag.")
    add("=" * 70)

    return "\n".join(lines)



# =====================================================================
# MAIN — ORCHESTRATION
# =====================================================================
def main():
    if len(sys.argv) < 2:
        print("Usage: python backup_planner.py <config-file>")
        return

    config_path = sys.argv[1]
    config = load_config(config_path)

    if config is None:
        print("Exiting due to configuration load error.")
        return

    is_valid, errors = validate_config(config)

    if not is_valid:
        print("\nCONFIG VALIDATION FAILED:")
        for err in errors:
            print(f" - {err}")
        print("\nFix the above issues and try again.")
        return

    simulation_data = simulate_backup(config)
    report_text = generate_report(simulation_data)

    print(report_text)



if __name__ == "__main__":
    main()