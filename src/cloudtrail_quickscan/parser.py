import json
from pathlib import Path
from typing import Any


def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Load events from a CloudTrail JSON file.

    CloudTrail exports usually store events under the "Records" key. For small
    lab files, this function also accepts a plain list of event objects.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    if isinstance(data, dict) and isinstance(data.get("Records"), list):
        return [event for event in data["Records"] if isinstance(event, dict)]

    if isinstance(data, list):
        return [event for event in data if isinstance(event, dict)]

    raise ValueError("Expected a CloudTrail file with a Records list")
