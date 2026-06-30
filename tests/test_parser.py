import json
import tempfile
import unittest
from pathlib import Path

from cloudtrail_quickscan.parser import load_events


class ParserTest(unittest.TestCase):
    def test_load_events_from_records_object(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.json"
            path.write_text(json.dumps({"Records": [{"eventName": "ConsoleLogin"}]}))

            events = load_events(path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["eventName"], "ConsoleLogin")

    def test_load_events_from_plain_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.json"
            path.write_text(json.dumps([{"eventName": "CreateUser"}]))

            events = load_events(path)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["eventName"], "CreateUser")


if __name__ == "__main__":
    unittest.main()
