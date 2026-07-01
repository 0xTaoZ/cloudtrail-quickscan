# Investigation notes

These notes are short on purpose. They are reminders for what I would check after a finding appears.

## Failed console login

- Check if the source IP is expected.
- Look for repeated failures from the same user or IP.
- Check if a successful login happened soon after the failures.

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

## Uncommon region

- Confirm if the account normally uses this AWS region.
- Check if more events happened in the same region.
- Look for IAM, compute, or logging changes around the same time.
