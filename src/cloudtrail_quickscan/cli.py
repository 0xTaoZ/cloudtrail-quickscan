import argparse
import json
from collections import Counter

from .parser import load_events
from .rules import scan_events

SEVERITY_ORDER = ("HIGH", "MED", "LOW")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cloudtrail-quickscan",
        description="Check a CloudTrail JSON file for a few suspicious patterns.",
    )
    parser.add_argument("path", help="Path to a CloudTrail JSON file")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only print the finding counts",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print findings as JSON for scripts",
    )
    args = parser.parse_args()

    events = load_events(args.path)
    findings = scan_events(events)

    if args.json:
        print_json_report(events_count=len(events), findings=findings)
    else:
        print_report(events_count=len(events), findings=findings, summary_only=args.summary_only)


def print_report(events_count: int, findings: list, summary_only: bool = False) -> None:
    print("CloudTrail Quickscan")
    print(f"Events checked: {events_count}")
    print(f"Findings: {len(findings)}")

    if not findings:
        print("\nNo findings from the current rules.")
        return

    counts = Counter(finding.severity for finding in findings)
    print(
        "Severity: "
        + ", ".join(
            f"{severity}={counts[severity]}"
            for severity in SEVERITY_ORDER
            if counts[severity]
        )
    )

    if summary_only:
        return

    print()
    for finding in findings:
        print(f"{finding.severity:<5} {finding.title}")
        print(f"      user: {finding.user}")
        print(f"      source ip: {finding.source_ip}")
        print(f"      event: {finding.event_name}")
        print(f"      region: {finding.region}")
        print(f"      time: {finding.event_time}")
        print(f"      note: {finding.detail}")


def print_json_report(events_count: int, findings: list) -> None:
    report = {
        "events_checked": events_count,
        "findings_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
