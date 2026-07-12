# cloudtrail-quickscan

A small Python tool for checking AWS CloudTrail JSON logs.

It loads CloudTrail events, finds a few suspicious patterns, and prints a short report that is easy to read.

This is not a full SIEM or a cloud security platform. It is meant to be a small helper for quick log review and cloud security labs.

## What it checks

- failed console logins
- root account activity
- IAM policy and access key changes
- security group changes
- CloudTrail logging changes, such as `DeleteTrail` or `StopLogging`
- S3 bucket exposure changes, such as public ACLs or public access block removal
- denied AWS API calls, such as `AccessDenied` or `UnauthorizedOperation`
- events from unusual AWS regions

## Quick start

```bash
PYTHONPATH=src python3 -m cloudtrail_quickscan samples/cloudtrail_sample.json
```

JSON output for scripts:

```bash
PYTHONPATH=src python3 -m cloudtrail_quickscan samples/cloudtrail_sample.json --json
```

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

The same test command runs in GitHub Actions.

## Example output

```text
CloudTrail Quickscan
Events checked: 7
Findings: 8
Severity: HIGH=3, MED=4, LOW=1

MED   Failed console login
MED   IAM change: CreateAccessKey
MED   Security group change: AuthorizeSecurityGroupIngress
LOW   Event from uncommon region: ap-south-1
HIGH  Root account activity
HIGH  CloudTrail logging change: DeleteTrail
HIGH  S3 bucket exposure change: PutBucketAcl
MED   API call denied: ListUsers
```

## Project plan

- keep the parser small and readable
- add more detection rules slowly
- add tests for every rule
- keep JSON output useful for small scripts
- add short notes about how to investigate each finding

## Notes

The sample data is fake and only used for testing.

Short triage notes are in [docs/investigation-notes.md](docs/investigation-notes.md).
Basic contribution notes are in [CONTRIBUTING.md](CONTRIBUTING.md).
