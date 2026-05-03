"""
Core data models for malware behavior analysis
"""

from datetime import datetime


class ObservedBehavior:
    """
    Represents a single observed malware behavior from sandbox analysis.
    """

    def __init__(self, behavior_type, value, timestamp):
        self.behavior_type = behavior_type
        self.value = value
        self.timestamp = datetime.fromisoformat(timestamp.replace("Z", ""))

    def __repr__(self):
        return (
            f"ObservedBehavior(type={self.behavior_type}, "
            f"value={self.value}, "
            f"timestamp={self.timestamp.isoformat()})"
        )


class AttackTechniqueMapper:
    """
    Rule-based mapper from observed malware behaviors
    to MITRE ATT&CK techniques.
    """

    def __init__(self):
        self.behaviors = []

        # MVP rule set (Week 14)
        self.mapping_rules = {
            "api_call": {
                "CreateRemoteThread": ("T1055", 0.9),
                "VirtualAllocEx": ("T1055", 0.8),
            },
            "registry_modification": {
                "Run": ("T1547.001", 0.85),
            },
            "network_connection": {
                "*": ("T1071", 0.75),
            },
        }

    def add_behavior(self, behavior):
        """Add an ObservedBehavior to be analyzed"""
        self.behaviors.append(behavior)

    def map_behaviors(self):
        """ 
        Apply rule-based mappings to all behaviors.
        Returns:
          - tagged behaviors list
          - technique frequency dictionary
        """
        tagged = []
        frequency = {}

        for behavior in self.behaviors:
            result = self._map_single_behavior(behavior)

            if result:
                tagged.append(result)         
            else:
                tagged.append({
                    "behavior": behavior.value,
                    "mapped_techniques": [],
                    "confidence": 0.0,
                    "mapping_status": "unmapped"
                })

        return tagged, frequency
    def _map_single_behavior(self, behavior):
        """
        Map a single behavior to ATT&CK techniques.
        Returns None if no mapping matches.
        """
        rules = self.mapping_rules.get(behavior.behavior_type, {})

        for key, (technique, confidence) in rules.items():
            if key == "*" or key in behavior.value:
                return {
                    "behavior": self._normalize_behavior_name(behavior),
                    "mapped_techniques": [technique],
                    "confidence": confidence,
                }

        return None

    @staticmethod
    def _normalize_behavior_name(behavior):
        if behavior.behavior_type == "registry_modification":
            return "Registry Run Key Modification"
        if behavior.behavior_type == "network_connection":
            return "Outbound Network Connection"
        return behavior.value
    


