import pytest
from src.models import AttackTechniqueMapper, ObservedBehavior

def test_process_injection_mapping():
    mapper = AttackTechniqueMapper()
    behavior = ObservedBehavior(
        "api_call",
        "CreateRemoteThread",
        "2024-03-15T14:23:10Z"
    )
    mapper.add_behavior(behavior)

    tagged, freq = mapper.map_behaviors()

    assert tagged[0]["mapped_techniques"] == ["T1055"]
    assert freq["T1055"] == 1


def test_unmapped_behavior():
    mapper = AttackTechniqueMapper()
    behavior = ObservedBehavior(
        "api_call",
        "UnknownAPI",
        "2024-03-15T14:23:10Z"
    )
    mapper.add_behavior(behavior)

    tagged, freq = mapper.map_behaviors()

    assert tagged[0]["mapped_techniques"] == []
    assert tagged[0]["confidence"] == 0.0


def test_empty_behavior_list():
    mapper = AttackTechniqueMapper()
    tagged, freq = mapper.map_behaviors()

    assert tagged == []
    assert freq == {}