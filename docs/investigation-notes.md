# Investigation notes

These notes are short on purpose. They are reminders for what I would check after a finding appears.

## Failed console login

- Check if the source IP is expected.
- Look for repeated failures from the same user or IP.
- Check if a successful login happened soon after the failures.

## Console login without MFA

- Confirm whether the user or role should require MFA.
- Check if this was a break-glass login or a lab account.
- Review nearby IAM changes from the same source IP.

## Root account activity

- Confirm if the action was planned.
- Check if MFA is enabled for the root account.
- Review nearby events from the same source IP.

## IAM changes

- Check who made the change and why.
- Review the policy or access key that was created or changed.
- Look for follow-up actions using the new permission.

## Security group changes

- Check if the change opened access to `0.0.0.0/0`.
- Review the port and protocol.
- Compare the change with the expected lab or production setup.

## CloudTrail logging changes

- Confirm if the logging change was planned maintenance.
- Check who made the change, from which source IP, and which role or user was used.
- Look for IAM, network, or compute activity right before and after the logging change.

## S3 bucket exposure changes

- Check whether the bucket should be public.
- Review the bucket policy, ACL, and public access block settings together.
- Look for object reads, object writes, or policy changes from the same user or IP.

## Denied API calls

- Check whether the denied action matches the user's expected role.
- Look for repeated denied calls from the same source IP or access key.
- Review nearby successful actions to see if the same identity found another path.

## Uncommon region

- Confirm if the account normally uses this AWS region.
- Check if more events happened in the same region.
- Look for IAM, compute, or logging changes around the same time.
