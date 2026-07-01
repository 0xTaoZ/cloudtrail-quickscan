from typing import Any

from .models import Finding, get_user_name

IAM_CHANGE_EVENTS = {
    "AttachUserPolicy",
    "CreateAccessKey",
    "CreatePolicy",
    "CreateUser",
    "DeleteUserPolicy",
    "DetachUserPolicy",
    "PutRolePolicy",
    "PutUserPolicy",
}

SECURITY_GROUP_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
}

CLOUDTRAIL_LOGGING_EVENTS = {
    "DeleteTrail",
    "PutEventSelectors",
    "StopLogging",
    "UpdateTrail",
}

COMMON_REGIONS = {
    "eu-central-1",
    "eu-west-1",
    "us-east-1",
    "us-west-2",
}


def scan_events(events: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []

    for event in events:
        findings.extend(scan_event(event))

    return findings


def scan_event(event: dict[str, Any]) -> list[Finding]:
    checks = [
        check_failed_console_login,
        check_root_activity,
        check_iam_change,
        check_security_group_change,
        check_cloudtrail_logging_change,
        check_uncommon_region,
    ]

    findings: list[Finding] = []
    for check in checks:
        finding = check(event)
        if finding:
            findings.append(finding)
    return findings


def check_failed_console_login(event: dict[str, Any]) -> Finding | None:
    if event.get("eventName") != "ConsoleLogin":
        return None

    response = event.get("responseElements") or {}
    if response.get("ConsoleLogin") != "Failure":
        return None

    return make_finding(
        event,
        severity="MED",
        title="Failed console login",
        detail="A console login failed. This can be normal, but repeated failures are worth checking.",
    )


def check_root_activity(event: dict[str, Any]) -> Finding | None:
    identity = event.get("userIdentity") or {}
    if identity.get("type") != "Root":
        return None

    return make_finding(
        event,
        severity="HIGH",
        title="Root account activity",
        detail="The root account was used. This should be rare in most AWS accounts.",
    )


def check_iam_change(event: dict[str, Any]) -> Finding | None:
    event_name = event.get("eventName")
    if event_name not in IAM_CHANGE_EVENTS:
        return None

    return make_finding(
        event,
        severity="MED",
        title=f"IAM change: {event_name}",
        detail="IAM permissions or access keys changed.",
    )


def check_security_group_change(event: dict[str, Any]) -> Finding | None:
    event_name = event.get("eventName")
    if event_name not in SECURITY_GROUP_EVENTS:
        return None

    return make_finding(
        event,
        severity="MED",
        title=f"Security group change: {event_name}",
        detail="Network access rules changed.",
    )


def check_cloudtrail_logging_change(event: dict[str, Any]) -> Finding | None:
    event_name = event.get("eventName")
    if event_name not in CLOUDTRAIL_LOGGING_EVENTS:
        return None

    severity = "HIGH" if event_name in {"DeleteTrail", "StopLogging"} else "MED"
    return make_finding(
        event,
        severity=severity,
        title=f"CloudTrail logging change: {event_name}",
        detail="CloudTrail logging was disabled, deleted, or changed.",
    )


def check_uncommon_region(event: dict[str, Any]) -> Finding | None:
    region = event.get("awsRegion")
    if not region or region in COMMON_REGIONS:
        return None

    return make_finding(
        event,
        severity="LOW",
        title=f"Event from uncommon region: {region}",
        detail="The event happened outside the small region allow-list used by this lab.",
    )


def make_finding(event: dict[str, Any], severity: str, title: str, detail: str) -> Finding:
    return Finding(
        severity=severity,
        title=title,
        event_name=str(event.get("eventName", "unknown")),
        user=get_user_name(event),
        source_ip=str(event.get("sourceIPAddress", "unknown")),
        region=str(event.get("awsRegion", "unknown")),
        event_time=str(event.get("eventTime", "unknown")),
        detail=detail,
    )
