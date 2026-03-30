# core/filter.py

def filter_indicators(indicators, min_conf=85, levels=None, types=None):
    """
    Filter indicators by confidence, threat level, and type.
    Defaults:
        min_conf = 85
        levels   = ["high", "critical"]
        types    = ["ip", "domain"]
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