import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

REQUIRED_PATHS = ["models.py", "utils.py"]
for file in REQUIRED_PATHS:
    if not os.path.isfile(file):
        raise RuntimeError(f"Required file missing: {file}")





"""
Malware Behavior to MITRE ATT&CK Technique Mapper

Week 14 MVP
- Reads malware behavior JSON
- Maps behaviors to ATT&CK techniques
- Outputs structured analysis report
"""

import argparse
import logging
import sys

from models import AttackTechniqueMapper
from utils import load_behaviors_from_file, save_results_to_file


def configure_cli():
    """
    Configure command-line argument parsing.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Analyze malware behavior data and map observed actions "
            "to MITRE ATT&CK techniques."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to input JSON file containing observed malware behaviors"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path to output JSON file for ATT&CK mapping results"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )

    return parser.parse_args()


def configure_logging(verbose=False):
    """
    Configure application logging.
    """
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s"
    )


def main():
    """
    Main program execution flow.
    """
    args = configure_cli()
    configure_logging(args.verbose)

    logging.info("Starting MITRE ATT&CK malware behavior analysis")

    try:
        # Load input data
        metadata, behaviors = load_behaviors_from_file(args.input)

        logging.info(
            "Loaded %d behaviors for sample %s",
            len(behaviors),
            metadata.get("sample_id", "UNKNOWN")
        )

        # Initialize and populate mapper
        mapper = AttackTechniqueMapper()
        for behavior in behaviors:
            mapper.add_behavior(behavior)

        logging.debug("Beginning ATT&CK mapping process")

        # Perform analysis
        tagged_behaviors, technique_frequency = mapper.map_behaviors()

        # Save output
        save_results_to_file(
            sample_id=metadata.get("sample_id", "UNKNOWN"),
            tagged_behaviors=tagged_behaviors,
            technique_frequency=technique_frequency,
            total_behaviors=len(behaviors),
            output_filepath=args.output
        )

        logging.info("Analysis completed successfully")

    except FileNotFoundError:
        logging.error("Input file not found: %s", args.input)
        sys.exit(1)

    except Exception as exc:
        logging.error("Analysis failed: %s", exc)
        sys.exit("ERROR: Analysis failed. Run with --verbose for details.")


if __name__ == "__main__":
    main()

logging.debug("Loaded mapping rules: %d categories", len(mapper.mapping_rules))
