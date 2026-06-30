import json

from cloudtrail_quickscan.parser import load_events


def test_load_events_from_records_object(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps({"Records": [{"eventName": "ConsoleLogin"}]}))

    events = load_events(path)

    assert len(events) == 1
    assert events[0]["eventName"] == "ConsoleLogin"


def test_load_events_from_plain_list(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps([{"eventName": "CreateUser"}]))

    events = load_events(path)

    assert len(events) == 1
    assert events[0]["eventName"] == "CreateUser"
