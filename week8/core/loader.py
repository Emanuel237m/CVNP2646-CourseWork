import json

def load_feed(filepath):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found → {filepath}")
    except json.JSONDecodeError:
        print(f"ERROR: JSON parsing failed → {filepath}")
    return None


def load_all_feeds():
    """
    Loads VendorA, VendorB, VendorC feeds and returns a list of tuples:
    (indicator_dict, vendor_name)
    """
    all_raw = []

    feeds = {
        "VendorA": ("vendor_a.json", "indicators"),
        "VendorB": ("vendor_b.json", "items"),
        "VendorC": ("vendor_c.json", "data")
    }

    for vendor, (filepath, key) in feeds.items():
        feed = load_feed(filepath)
        if feed and key in feed:
            for item in feed[key]:
                all_raw.append((item, vendor))

    return all_raw