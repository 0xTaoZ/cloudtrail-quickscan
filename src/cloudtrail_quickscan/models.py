from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    event_name: str
    user: str
    source_ip: str
    region: str
    event_time: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "title": self.title,
            "event_name": self.event_name,
            "user": self.user,
            "source_ip": self.source_ip,
            "region": self.region,
            "event_time": self.event_time,
            "detail": self.detail,
        }


def get_user_name(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity") or {}
    return (
        identity.get("userName")
        or identity.get("arn")
        or identity.get("principalId")
        or "unknown"
    )
