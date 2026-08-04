import unittest

from cloudtrail_quickscan.rules import scan_event, scan_events


class RuleTest(unittest.TestCase):
    def test_failed_console_login_is_medium_finding(self):
        event = {
            "eventName": "ConsoleLogin",
            "awsRegion": "eu-central-1",
            "eventTime": "2026-06-28T08:15:00Z",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "responseElements": {"ConsoleLogin": "Failure"},
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MED")
        self.assertEqual(findings[0].title, "Failed console login")
        self.assertEqual(findings[0].source_ip, "unknown")

    def test_finding_records_source_ip(self):
        event = {
            "eventName": "CreateAccessKey",
            "awsRegion": "eu-central-1",
            "eventTime": "2026-06-28T08:18:00Z",
            "sourceIPAddress": "198.51.100.10",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
        }

        findings = scan_event(event)

        self.assertEqual(findings[0].source_ip, "198.51.100.10")

    def test_root_activity_is_high_finding(self):
        event = {
            "eventName": "ListBuckets",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T10:11:00Z",
            "userIdentity": {"type": "Root", "principalId": "111122223333"},
        }

        findings = scan_event(event)

        self.assertTrue(any(finding.title == "Root account activity" for finding in findings))
        self.assertTrue(any(finding.severity == "HIGH" for finding in findings))

    def test_scan_events_combines_findings(self):
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

        self.assertIn("IAM change: CreateAccessKey", titles)
        self.assertIn("Event from uncommon region: ap-south-1", titles)

    def test_delete_trail_is_high_logging_finding(self):
        event = {
            "eventName": "DeleteTrail",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T10:11:00Z",
            "sourceIPAddress": "192.0.2.50",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].title, "CloudTrail logging change: DeleteTrail")

    def test_update_trail_is_medium_logging_finding(self):
        event = {
            "eventName": "UpdateTrail",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T10:22:00Z",
            "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::111122223333:assumed-role/Admin/student"},
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MED")
        self.assertEqual(findings[0].title, "CloudTrail logging change: UpdateTrail")

    def test_delete_public_access_block_is_high_s3_finding(self):
        event = {
            "eventName": "DeletePublicAccessBlock",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T10:45:00Z",
            "sourceIPAddress": "198.51.100.22",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].title, "S3 bucket exposure change: DeletePublicAccessBlock")

    def test_public_bucket_acl_grant_is_high_s3_finding(self):
        event = {
            "eventName": "PutBucketAcl",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T11:00:00Z",
            "sourceIPAddress": "198.51.100.23",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "requestParameters": {
                "AccessControlPolicy": {
                    "AccessControlList": {
                        "Grant": {
                            "Grantee": {
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
                            }
                        }
                    }
                }
            },
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(
            findings[0].detail,
            "An S3 bucket ACL included a public or authenticated-users grant.",
        )

    def test_access_denied_error_is_medium_finding(self):
        event = {
            "eventName": "ListUsers",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T11:20:00Z",
            "sourceIPAddress": "198.51.100.24",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "errorCode": "AccessDenied",
            "errorMessage": "User is not authorized to perform iam:ListUsers",
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MED")
        self.assertEqual(findings[0].title, "API call denied: ListUsers")
        self.assertEqual(
            findings[0].detail,
            "An AWS API call was denied. Repeated denied calls can show probing or missing permissions.",
        )

    def test_console_login_without_mfa_is_medium_finding(self):
        event = {
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T11:45:00Z",
            "sourceIPAddress": "198.51.100.25",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "responseElements": {"ConsoleLogin": "Success"},
            "additionalEventData": {"MFAUsed": "No"},
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MED")
        self.assertEqual(findings[0].title, "Console login without MFA")
        self.assertEqual(
            findings[0].detail,
            "A console login succeeded without MFA. Confirm whether this identity should require MFA.",
        )

    def test_root_access_key_creation_is_high_finding(self):
        event = {
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T12:00:00Z",
            "sourceIPAddress": "198.51.100.29",
            "userIdentity": {"type": "Root", "principalId": "111122223333"},
        }

        findings = scan_event(event)

        self.assertTrue(
            any(
                finding.severity == "HIGH"
                and finding.title == "Root access key created"
                for finding in findings
            )
        )

    def test_iam_user_access_key_creation_keeps_generic_iam_finding(self):
        event = {
            "eventName": "CreateAccessKey",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T12:05:00Z",
            "sourceIPAddress": "198.51.100.30",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
        }

        findings = scan_event(event)
        titles = [finding.title for finding in findings]

        self.assertIn("IAM change: CreateAccessKey", titles)
        self.assertNotIn("Root access key created", titles)

    def test_administrator_policy_attachment_is_high_finding(self):
        event = {
            "eventName": "AttachRolePolicy",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T12:08:00Z",
            "sourceIPAddress": "198.51.100.32",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "requestParameters": {
                "roleName": "break-glass-role",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        }

        findings = scan_event(event)

        self.assertTrue(
            any(
                finding.severity == "HIGH"
                and finding.title == "AdministratorAccess policy attached"
                for finding in findings
            )
        )

    def test_public_ssh_security_group_ingress_is_high_finding(self):
        event = {
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T12:10:00Z",
            "sourceIPAddress": "198.51.100.26",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "requestParameters": {
                "ipPermissions": {
                    "items": [
                        {
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [{"cidrIp": "0.0.0.0/0"}],
                            },
                        }
                    ]
                }
            },
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 2)
        self.assertTrue(
            any(
                finding.severity == "HIGH"
                and finding.title == "Public admin-port ingress: SSH"
                for finding in findings
            )
        )

    def test_public_ipv6_rdp_security_group_ingress_is_high_finding(self):
        event = {
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T12:20:00Z",
            "sourceIPAddress": "198.51.100.27",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "requestParameters": {
                "ipPermissions": {
                    "items": [
                        {
                            "fromPort": 3389,
                            "toPort": 3389,
                            "ipv6Ranges": {
                                "items": [{"cidrIpv6": "::/0"}],
                            },
                        }
                    ]
                }
            },
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 2)
        self.assertTrue(
            any(
                finding.severity == "HIGH"
                and finding.title == "Public admin-port ingress: RDP"
                for finding in findings
            )
        )

    def test_private_admin_port_security_group_ingress_is_not_public_finding(self):
        event = {
            "eventName": "AuthorizeSecurityGroupIngress",
            "awsRegion": "us-east-1",
            "eventTime": "2026-06-28T12:30:00Z",
            "sourceIPAddress": "198.51.100.28",
            "userIdentity": {"type": "IAMUser", "userName": "student-lab"},
            "requestParameters": {
                "ipPermissions": {
                    "items": [
                        {
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {
                                "items": [{"cidrIp": "10.0.0.0/8"}],
                            },
                        }
                    ]
                }
            },
        }

        findings = scan_event(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "Security group change: AuthorizeSecurityGroupIngress")


if __name__ == "__main__":
    unittest.main()
