"""
Utility functions for JSON input/output
"""

import json
import logging
from models import ObservedBehavior


def load_behaviors_from_file(filepath):
    """
    Load malware behaviors from a JSON file and return:
      - sample metadata
      - list of ObservedBehavior objects
    """
    try:
        with open(filepath, "r") as f:
            data = json.load(f)

        metadata = data.get("sample_metadata", {})
        raw_behaviors = data.get("observed_behaviors", [])

        behaviors = []
        for item in raw_behaviors:
            behavior = ObservedBehavior(
                behavior_type=item["type"],
                value=item["value"],
                timestamp=item["timestamp"]
            )
            behaviors.append(behavior)

        logging.info(f"Loaded {len(behaviors)} behaviors from {filepath}")
        return metadata, behaviors

    except FileNotFoundError:
        logging.error(f"Input file not found: {filepath}")
        raise

    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON format: {e}")
        raise

    except KeyError as e:
        logging.error(f"Missing required field in JSON: {e}")
        raise
        logging.debug("Parsing input JSON structure")

from datetime import datetime
if "observed_behaviors" not in data:
    raise KeyError("Missing 'observed_behaviors' field in input JSON")

if not isinstance(data["observed_behaviors"], list):
    raise TypeError("'observed_behaviors' must be a list")

def save_results_to_file(
    sample_id,
    tagged_behaviors,
    technique_frequency,
    total_behaviors,
    output_filepath
):
    """
    Save analysis results to a JSON file in report format.
    """
    logging.debug("Writing %d tagged behaviors to output",
              len(tagged_behaviors))
    output_data = {
        "sample_id": sample_id,
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        "tagged_behaviors": tagged_behaviors,
        "technique_frequency": technique_frequency,
        "summary": {
            "total_behaviors_analyzed": total_behaviors,
            "unique_techniques_detected": len(technique_frequency)
        }
    }

    try:
        with open(output_filepath, "w") as f:
            json.dump(output_data, f, indent=2)

        logging.info(f"Results written to {output_filepath}")

    except IOError as e:
        logging.error(f"Failed to write output file: {e}")
        raise
