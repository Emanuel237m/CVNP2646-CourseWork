# core/deduper.py

def deduplicate_indicators(indicators):
    """
    Remove duplicates by (type, value).
    Keep the indicator with the highest confidence and merge source lists.
    Returns a tuple:
        (unique_indicators_list, duplicate_count)
    """

    unique = {}  # key: (type, value)
    duplicate_count = 0

    for ind in indicators:
        key = (ind["type"], ind["value"])

        if key not in unique:
            unique[key] = ind

        else:
            duplicate_count += 1
            existing = unique[key]

            # Keep indicator with higher confidence
            if ind["confidence"] > existing["confidence"]:
                # merge previous sources into the new (better) indicator
                ind["sources"].extend(existing["sources"])
                unique[key] = ind
            else:
                # merge new indicator's sources into the existing one
                existing["sources"].extend(ind["sources"])

    return list(unique.values()), duplicate_count
