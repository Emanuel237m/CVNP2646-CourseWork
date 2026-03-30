from collections import Counter

def generate_statistics(loaded_count, valid_list, deduped_list, filtered_list):

    type_counts = Counter(ind["type"] for ind in filtered_list)
    severity_counts = Counter(ind["threat_level"] for ind in filtered_list)

    source_counts = Counter()
    for ind in deduped_list:
        for src in ind["sources"]:
            source_counts[src] += 1

    return {
        "total_loaded": loaded_count,
        "valid_count": len(valid_list),
        "unique_after_dedup": len(deduped_list),
        "filtered_count": len(filtered_list),
        "duplicates_removed": loaded_count - len(deduped_list),
        "type_distribution": dict(type_counts),
        "threat_distribution": dict(severity_counts),
        "source_contribution": dict(source_counts),
    }