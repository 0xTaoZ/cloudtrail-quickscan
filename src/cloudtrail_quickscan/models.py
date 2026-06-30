from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    event_name: str
    user: str
    region: str
    event_time: str
    detail: str


def get_user_name(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity") or {}
    return (
        identity.get("userName")
        or identity.get("arn")
        or identity.get("principalId")
        or "unknown"
    )
