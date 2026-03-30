# core/validator.py

def validate_indicators(indicators):
    """
    Validate normalized indicators — ensures required fields exist,
    types are valid, confidence is numeric and within 0–100.
    Returns:
        valid_list, error_count, error_messages
    """

    valid = []
    errors = []

    allowed_types = {"ip", "domain", "hash", "url"}

    for idx, ind in enumerate(indicators):

        # Required fields check
        required = ["id", "type", "value", "confidence"]
        missing = [f for f in required if ind.get(f) is None]

        if missing:
            errors.append(f"Indicator {idx}: missing fields {missing}")
            continue

        # Type check
        if ind["type"] not in allowed_types:
            errors.append(f"Indicator {idx}: invalid type '{ind['type']}'")
            continue

        # Value check
        if not isinstance(ind["value"], str) or ind["value"].strip() == "":
            errors.append(f"Indicator {idx}: empty or invalid value")
            continue

        # Confidence check
        try:
            conf = float(ind["confidence"])
        except ValueError:
            errors.append(f"Indicator {idx}: confidence not numeric")
            continue

        if not (0 <= conf <= 100):
            errors.append(f"Indicator {idx}: confidence out of range (0–100)")
            continue

        # Normalize confidence
        ind["confidence"] = conf

        valid.append(ind)

    return valid, len(errors), errors