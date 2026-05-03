import json
import logging
from datetime import datetime
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

        # ✅ Validation
        if "observed_behaviors" not in data:
            raise KeyError("Missing 'observed_behaviors' field in input JSON")

        if not isinstance(data["observed_behaviors"], list):
            raise TypeError("'observed_behaviors' must be a list")

        metadata = data.get("sample_metadata", {})
        raw_behaviors = data.get("observed_behaviors", [])

        behaviors = []
        required_fields = {"type", "value", "timestamp"}

        for item in raw_behaviors:
            if not required_fields.issubset(item):
                raise KeyError(
                    f"Behavior missing required fields: {required_fields - item.keys()}"
                )

            behavior = ObservedBehavior(
                behavior_type=item["type"],
                value=item["value"],
                timestamp=item["timestamp"]
            )
            behaviors.append(behavior)

        logging.info("Loaded %d behaviors from %s", len(behaviors), filepath)
        return metadata, behaviors

    except FileNotFoundError:
        logging.error("Input file not found: %s", filepath)
        raise

    except json.JSONDecodeError as e:
        logging.error("Invalid JSON format: %s", e)
        raise


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

        logging.info("Results written to %s", output_filepath)

    except IOError as e:
        logging.error("Failed to write output file: %s", e)
        raise