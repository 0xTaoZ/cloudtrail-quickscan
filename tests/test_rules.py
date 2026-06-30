from cloudtrail_quickscan.rules import scan_event, scan_events


def test_failed_console_login_is_medium_finding():
    event = {
        "eventName": "ConsoleLogin",
        "awsRegion": "eu-central-1",
        "eventTime": "2026-06-28T08:15:00Z",
        "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
        "responseElements": {"ConsoleLogin": "Failure"},
    }

    findings = scan_event(event)

    assert len(findings) == 1
    assert findings[0].severity == "MED"
    assert findings[0].title == "Failed console login"


def test_root_activity_is_high_finding():
    event = {
        "eventName": "ListBuckets",
        "awsRegion": "us-east-1",
        "eventTime": "2026-06-28T10:11:00Z",
        "userIdentity": {"type": "Root", "principalId": "111122223333"},
    }

    findings = scan_event(event)

    assert any(finding.title == "Root account activity" for finding in findings)
    assert any(finding.severity == "HIGH" for finding in findings)


def test_scan_events_combines_findings():
    events = [
        {
            "eventName": "CreateAccessKey",
            "awsRegion": "eu-central-1",
            "eventTime": "2026-06-28T08:18:00Z",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
        },
        {
            "eventName": "ListBuckets",
            "awsRegion": "ap-south-1",
            "eventTime": "2026-06-28T09:30:00Z",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
        },
    ]

    findings = scan_events(events)
    titles = [finding.title for finding in findings]

    assert "IAM change: CreateAccessKey" in titles
    assert "Event from uncommon region: ap-south-1" in titles
