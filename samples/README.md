# Samples

The JSON file in this folder is fake CloudTrail-style data.

It is only here so the tool can be tested without using a real AWS account or real company logs.

The sample includes a failed login, IAM changes, access key deactivation, IAM console password creation, MFA device removal, a permissions boundary removal, root access key creation, security group changes, an unusual region event, CloudTrail deletion event, S3 ACL change, denied API call, console login without MFA, and public SSH ingress.

It also repeats a few source IPs and users so the summary count output has useful data.

`monitoring_changes.json` pairs two synthetic GuardDuty disable requests: one
without an error and one denied request. Run:

```bash
PYTHONPATH=src python3 -m cloudtrail_quickscan samples/monitoring_changes.json
```

Expect one HIGH monitoring-disable finding and one MED denied-call finding.
The denied request must not add a second monitoring-disable finding.
