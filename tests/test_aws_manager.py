from unittest.mock import MagicMock
from botocore.exceptions import ClientError
from app.aws_manager import AwsManager


class Settings:
    aws_profile = None
    aws_region = "ap-south-1"
    aws_account_id = "618046392939"
    s3_bucket = "example-bucket"


def manager():
    aws = AwsManager.__new__(AwsManager)
    aws.settings = Settings()
    aws.iam = MagicMock()
    aws.s3control = MagicMock()
    aws.s3 = MagicMock()
    return aws


def test_existing_group_is_reused():
    aws = manager()
    aws.iam.get_group.return_value = {"Group": {"GroupName": "ResearchGroup"}, "Users": []}
    aws.ensure_group("ResearchGroup")
    aws.iam.create_group.assert_not_called()


def test_missing_group_is_created():
    aws = manager()
    aws.iam.get_group.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetGroup")
    aws.ensure_group("ResearchGroup")
    aws.iam.create_group.assert_called_once_with(GroupName="ResearchGroup")


def test_unchanged_iam_policy_does_not_create_duplicate_version():
    aws = manager()
    document = {"Version": "2012-10-17", "Statement": []}
    aws.iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    aws.iam.get_policy_version.return_value = {"PolicyVersion": {"Document": document}}
    aws.ensure_iam_policy("ResearchPolicy", "ResearchGroup", document)
    aws.iam.create_policy.assert_not_called()
    aws.iam.create_policy_version.assert_not_called()
    aws.iam.attach_group_policy.assert_called_once()


def test_existing_access_point_is_reused():
    aws = manager()
    aws.s3control.get_access_point.return_value = {"Bucket": "example-bucket", "AccessPointArn": "arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap"}
    aws.ensure_access_point("research-ap", "example-bucket")
    aws.s3control.create_access_point.assert_not_called()


def test_bucket_policy_reconcile_preserves_other_team_statement_and_single_statement_shape():
    import json
    from app.policy_generator import generate_bucket_policy

    aws = manager()
    unrelated = {"Sid": "S3AccessManagerresearch2Objects", "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}
    aws.s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Version": "2012-10-17", "Statement": unrelated})}
    generated = generate_bucket_policy(
        "research", "research/", ["write"], "example-bucket",
        "arn:aws:s3:ap-south-1:618046392939:accesspoint/research-ap",
    )
    reconciled = aws.reconcile_bucket_policy(generated, team="research")
    assert unrelated in reconciled["Statement"]
    assert len(reconciled["Statement"]) == 2
