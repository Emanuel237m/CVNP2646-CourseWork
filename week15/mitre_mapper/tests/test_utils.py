import pytest
from src.utils import load_behaviors_from_file

def test_invalid_json_structure(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{}")

    with pytest.raises(KeyError):
        load_behaviors_from_file(bad_file)


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        load_behaviors_from_file("does_not_exist.json")
