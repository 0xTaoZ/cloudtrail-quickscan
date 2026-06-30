# cloudtrail-quickscan

A small Python tool for checking AWS CloudTrail JSON logs.

I made this as a learning project for blue team and cloud security practice. The goal is simple: load CloudTrail events, find a few suspicious patterns, and print a report that is easy to read.

This is not a full SIEM or a cloud security platform. It is a small lab project for understanding what useful cloud logs look like.

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

Run tests:

```bash
python -m pytest
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

## Notes

The sample data is fake and only used for testing.
