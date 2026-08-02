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

S3_BUCKET_EXPOSURE_EVENTS = {
    "DeletePublicAccessBlock",
    "PutBucketAcl",
    "PutBucketPolicy",
}

ACCESS_DENIED_ERROR_MARKERS = {
    "AccessDenied",
    "AccessDeniedException",
    "Client.UnauthorizedOperation",
    "UnauthorizedOperation",
}

PUBLIC_ACL_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}

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
        check_console_login_without_mfa,
        check_root_activity,
        check_root_access_key_creation,
        check_iam_change,
        check_security_group_change,
        check_public_admin_port_ingress,
        check_cloudtrail_logging_change,
        check_s3_bucket_exposure_change,
        check_access_denied_error,
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


def check_console_login_without_mfa(event: dict[str, Any]) -> Finding | None:
    if event.get("eventName") != "ConsoleLogin":
        return None

    response = event.get("responseElements") or {}
    additional = event.get("additionalEventData") or {}
    if response.get("ConsoleLogin") != "Success" or additional.get("MFAUsed") != "No":
        return None

    return make_finding(
        event,
        severity="MED",
        title="Console login without MFA",
        detail="A console login succeeded without MFA. Confirm whether this identity should require MFA.",
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


def check_root_access_key_creation(event: dict[str, Any]) -> Finding | None:
    identity = event.get("userIdentity") or {}
    if event.get("eventName") != "CreateAccessKey" or identity.get("type") != "Root":
        return None

    return make_finding(
        event,
        severity="HIGH",
        title="Root access key created",
        detail="A root access key was created. Root long-term keys should normally not exist.",
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


def check_public_admin_port_ingress(event: dict[str, Any]) -> Finding | None:
    if event.get("eventName") != "AuthorizeSecurityGroupIngress":
        return None

    for permission in get_ip_permissions(event):
        admin_service = get_admin_service(permission)
        if admin_service and has_public_range(permission):
            return make_finding(
                event,
                severity="HIGH",
                title=f"Public admin-port ingress: {admin_service}",
                detail=(
                    f"{admin_service} was opened to a public IPv4 or IPv6 range. "
                    "Confirm this is expected and restricted by other controls."
                ),
            )
    return None


def get_ip_permissions(event: dict[str, Any]) -> list[dict[str, Any]]:
    request = event.get("requestParameters") or {}
    permissions = request.get("ipPermissions") or {}
    return as_list(permissions.get("items", permissions))


def get_admin_service(permission: dict[str, Any]) -> str | None:
    from_port = permission.get("fromPort")
    to_port = permission.get("toPort")
    for port, service in ADMIN_PORTS.items():
        if from_port is not None and to_port is not None and from_port <= port <= to_port:
            return service
    return None


def has_public_range(permission: dict[str, Any]) -> bool:
    for range_key, cidr_key in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")):
        ranges = permission.get(range_key) or {}
        for item in as_list(ranges.get("items", ranges)):
            if isinstance(item, dict) and item.get(cidr_key) in PUBLIC_CIDRS:
                return True
    return False


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


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


def check_s3_bucket_exposure_change(event: dict[str, Any]) -> Finding | None:
    event_name = event.get("eventName")
    if event_name not in S3_BUCKET_EXPOSURE_EVENTS:
        return None

    severity = "HIGH" if event_name == "DeletePublicAccessBlock" else "MED"
    detail = "An S3 bucket policy, ACL, or public access block setting changed."

    if has_public_acl_grant(event):
        severity = "HIGH"
        detail = "An S3 bucket ACL included a public or authenticated-users grant."

    return make_finding(
        event,
        severity=severity,
        title=f"S3 bucket exposure change: {event_name}",
        detail=detail,
    )


def has_public_acl_grant(event: dict[str, Any]) -> bool:
    request = event.get("requestParameters") or {}
    policy = request.get("AccessControlPolicy") or {}
    grants = policy.get("AccessControlList", {}).get("Grant", [])
    if isinstance(grants, dict):
        grants = [grants]

    for grant in grants:
        grantee = grant.get("Grantee", {}) if isinstance(grant, dict) else {}
        if grantee.get("URI") in PUBLIC_ACL_GROUP_URIS:
            return True
    return False


def check_access_denied_error(event: dict[str, Any]) -> Finding | None:
    error_code = str(event.get("errorCode", ""))
    if not any(marker in error_code for marker in ACCESS_DENIED_ERROR_MARKERS):
        return None

    return make_finding(
        event,
        severity="MED",
        title=f"API call denied: {event.get('eventName', 'unknown')}",
        detail="An AWS API call was denied. Repeated denied calls can show probing or missing permissions.",
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
