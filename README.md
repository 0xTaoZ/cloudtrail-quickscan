# cloudtrail-quickscan

A small Python tool for checking AWS CloudTrail JSON logs.

It loads CloudTrail events, finds a few suspicious patterns, and prints a short report that is easy to read.

This is not a full SIEM or a cloud security platform. It is meant to be a small helper for quick log review and cloud security labs.

## What it checks

- failed console logins
- root account activity
- IAM policy and access key changes
- security group changes
- events from unusual AWS regions

## Quick start

```bash
python -m cloudtrail_quickscan samples/cloudtrail_sample.json
```

JSON output for scripts:

```bash
python -m cloudtrail_quickscan samples/cloudtrail_sample.json --json
```

Run tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

## Example output

```text
CloudTrail Quickscan
Events checked: 6
Findings: 4

HIGH  Root account activity
MED   IAM change: CreateAccessKey
MED   Failed console login
LOW   Event from uncommon region: ap-south-1
```

## Project plan

- keep the parser small and readable
- add more detection rules slowly
- add tests for every rule
- maybe export findings to JSON later
- add a few notes about how to investigate each finding

## Notes

The sample data is fake and only used for testing.
