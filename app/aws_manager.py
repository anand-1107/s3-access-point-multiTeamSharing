import json
import logging
from botocore.exceptions import BotoCoreError, ClientError
import boto3
from app.policy_generator import bucket_policy_sid_prefix

logger = logging.getLogger(__name__)


class AwsManager:
    def __init__(self, settings):
        session = boto3.Session(profile_name=settings.aws_profile, region_name=settings.aws_region) if settings.aws_profile else boto3.Session(region_name=settings.aws_region)
        self.iam = session.client("iam")
        self.s3 = session.client("s3")
        self.s3control = session.client("s3control")
        self.settings = settings

    def _call(self, description, fn, **kwargs):
        logger.info("AWS operation=%s", description)
        try:
            return fn(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "AWS_ERROR")
            logger.exception("AWS operation failed: %s (%s)", description, code)
            raise RuntimeError(f"AWS operation {description} failed ({code})") from None
        except BotoCoreError as exc:
            logger.exception("AWS operation failed: %s", description)
            raise RuntimeError(f"AWS operation {description} failed ({type(exc).__name__})") from None

    def group_exists(self, name):
        try:
            self.iam.get_group(GroupName=name)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return False
            raise RuntimeError("AWS group lookup failed") from None

    def ensure_group(self, name):
        if not self.group_exists(name):
            self._call("create IAM group", self.iam.create_group, GroupName=name)

    def group_members(self, name):
        members = []
        marker = None
        while True:
            kwargs = {"GroupName": name}
            if marker:
                kwargs["Marker"] = marker
            response = self._call("list IAM group members", self.iam.get_group, **kwargs)
            members.extend(user["UserName"] for user in response.get("Users", []))
            if not response.get("IsTruncated"):
                return members
            marker = response.get("Marker")

    def iam_user_exists(self, username):
        try:
            self.iam.get_user(UserName=username)
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return False
            raise RuntimeError("AWS IAM user lookup failed") from None
        except BotoCoreError as exc:
            raise RuntimeError(f"AWS IAM user lookup failed ({type(exc).__name__})") from None

    def ensure_iam_user(self, username):
        try:
            self.iam.get_user(UserName=username)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise RuntimeError("AWS IAM user lookup failed") from None
            self._call("create IAM user", self.iam.create_user, UserName=username)

    def user_group_names(self, username):
        groups = []
        marker = None
        while True:
            kwargs = {"UserName": username}
            if marker:
                kwargs["Marker"] = marker
            response = self._call("list IAM user groups", self.iam.list_groups_for_user, **kwargs)
            groups.extend(group["GroupName"] for group in response.get("Groups", []))
            if not response.get("IsTruncated"):
                return groups
            marker = response.get("Marker")

    def remove_user_from_other_managed_team_groups(self, username, target_group):
        for group_name in self.user_group_names(username):
            if group_name == target_group:
                continue
            marker = None
            attached = []
            while True:
                kwargs = {"GroupName": group_name}
                if marker:
                    kwargs["Marker"] = marker
                response = self._call("list attached IAM group policies", self.iam.list_attached_group_policies, **kwargs)
                attached.extend(response.get("AttachedPolicies", []))
                if not response.get("IsTruncated"):
                    break
                marker = response.get("Marker")
            for policy in attached:
                try:
                    detail = self._call("inspect IAM group policy", self.iam.get_policy, PolicyArn=policy["PolicyArn"])["Policy"]
                except RuntimeError:
                    continue
                if detail.get("Description") == "Managed by S3 Access Manager":
                    self.remove_user_from_group(username, group_name)
                    break

    def add_user_to_group(self, username, group_name):
        self._call("add IAM user to team group", self.iam.add_user_to_group, UserName=username, GroupName=group_name)

    def remove_user_from_group(self, username, group_name):
        self._call("remove IAM user from team group", self.iam.remove_user_from_group, UserName=username, GroupName=group_name)

    def ensure_iam_policy(self, name, group_name, document):
        arn = f"arn:aws:iam::{self.settings.aws_account_id}:policy/{name}"
        try:
            policy = self.iam.get_policy(PolicyArn=arn)["Policy"]
            default = self.iam.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]
            if isinstance(default, str):
                default = json.loads(default)
            if default != document:
                versions = self.iam.list_policy_versions(PolicyArn=arn)["Versions"]
                if len(versions) >= 5:
                    oldest = sorted((v for v in versions if not v["IsDefaultVersion"]), key=lambda v: v["CreateDate"])[0]
                    self._call("delete old IAM policy version", self.iam.delete_policy_version, PolicyArn=arn, VersionId=oldest["VersionId"])
                self._call("update IAM policy", self.iam.create_policy_version, PolicyArn=arn, PolicyDocument=json.dumps(document), SetAsDefault=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise RuntimeError("AWS IAM policy update failed") from None
            self._call("create IAM policy", self.iam.create_policy, PolicyName=name, PolicyDocument=json.dumps(document), Description="Managed by S3 Access Manager")
        self._call("attach IAM policy to group", self.iam.attach_group_policy, GroupName=group_name, PolicyArn=arn)
        return arn

    def ensure_access_point(self, name, bucket):
        try:
            existing = self._call("get S3 access point", self.s3control.get_access_point, AccountId=self.settings.aws_account_id, Name=name)
            if existing.get("Bucket") != bucket:
                raise RuntimeError("Access point name is already associated with a different bucket")
            return existing
        except RuntimeError as exc:
            # AccessPointNotFound is expected when creating. Distinguish without exposing details.
            if "NoSuchAccessPoint" not in str(exc) and "NotFound" not in str(exc):
                raise
        return self._call("create S3 access point", self.s3control.create_access_point, AccountId=self.settings.aws_account_id, Name=name, Bucket=bucket)

    def set_access_point_policy(self, name, document):
        self._call("put S3 access point policy", self.s3control.put_access_point_policy, AccountId=self.settings.aws_account_id, Name=name, Policy=json.dumps(document))

    def get_access_point(self, name):
        return self._call("get S3 access point", self.s3control.get_access_point, AccountId=self.settings.aws_account_id, Name=name)

    def reconcile_bucket_policy(self, generated, team):
        bucket = self.settings.s3_bucket
        try:
            current = json.loads(self._call("get bucket policy", self.s3.get_bucket_policy, Bucket=bucket)["Policy"])
        except RuntimeError as exc:
            if "NoSuchBucketPolicy" not in str(exc):
                raise
            current = {"Version": "2012-10-17", "Statement": []}
        existing_statements = current.get("Statement", [])
        if isinstance(existing_statements, dict):
            existing_statements = [existing_statements]
        team_sids = {
            f"{bucket_policy_sid_prefix(team)}List",
            f"{bucket_policy_sid_prefix(team)}Objects",
        }

        # Remove the legacy direct-user statements created by the original
        # manual setup. The backend-managed model authorizes users through
        # their IAM group -> IAM policy -> Access Point, with the bucket
        # policy delegating requests to the Access Point.
        title = "".join(part.capitalize() for part in team.split("-"))
        if team == "ml":
            title = "ML"
        legacy_team_sids = {
            f"Allow{title}AccessPoint",
            f"Allow{title}Objects",
        }

        managed_sids = team_sids | legacy_team_sids
        current["Statement"] = [
            statement
            for statement in existing_statements
            if statement.get("Sid") not in managed_sids
        ] + generated["Statement"]
        self._call("put merged bucket policy", self.s3.put_bucket_policy, Bucket=bucket, Policy=json.dumps(current))
        return current

    def current_configuration(self, team, ap_name):
        try:
            ap = self.get_access_point(ap_name)
            policy = self._call("get access point policy", self.s3control.get_access_point_policy, AccountId=self.settings.aws_account_id, Name=ap_name)
            return {"access_point": ap, "access_point_policy": json.loads(policy["Policy"])}
        except RuntimeError as exc:
            if "NoSuchAccessPoint" in str(exc) or "NotFound" in str(exc):
                return None
            raise

    def delete_team_resources(self, team, group, policy_name, ap_name, bucket_generated):
        # Remove just this app's statements, then detach/delete its managed IAM policy.
        bucket = self.settings.s3_bucket
        try:
            current = json.loads(self.s3.get_bucket_policy(Bucket=bucket)["Policy"])
            team_sids = {f"{bucket_policy_sid_prefix(team)}List", f"{bucket_policy_sid_prefix(team)}Objects"}
            statements = current.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            kept = [statement for statement in statements if statement.get("Sid") not in team_sids]
            if kept:
                self.s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({**current, "Statement": kept}))
            else:
                self.s3.delete_bucket_policy(Bucket=bucket)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                raise RuntimeError("AWS bucket policy cleanup failed") from None
        arn = f"arn:aws:iam::{self.settings.aws_account_id}:policy/{policy_name}"
        try:
            self.iam.detach_group_policy(GroupName=group, PolicyArn=arn)
            for version in self.iam.list_policy_versions(PolicyArn=arn).get("Versions", []):
                if not version["IsDefaultVersion"]:
                    self.iam.delete_policy_version(PolicyArn=arn, VersionId=version["VersionId"])
            self.iam.delete_policy(PolicyArn=arn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("NoSuchEntity",):
                raise RuntimeError("AWS IAM policy cleanup failed") from None
        # Existing access points may be shared/managed externally; remove only their policy.
        try:
            self.s3control.delete_access_point_policy(AccountId=self.settings.aws_account_id, Name=ap_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("NoSuchAccessPoint", "NoSuchAccessPointPolicy"):
                raise RuntimeError("AWS access point policy cleanup failed") from None


    def get_iam_policy_document(self, policy_name):
        arn = f"arn:aws:iam::{self.settings.aws_account_id}:policy/{policy_name}"
        try:
            policy = self._call("get IAM policy", self.iam.get_policy, PolicyArn=arn)["Policy"]
            document = self._call("get IAM policy version", self.iam.get_policy_version, PolicyArn=arn, VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]
            return json.loads(document) if isinstance(document, str) else document
        except RuntimeError as exc:
            if "NoSuchEntity" in str(exc):
                return None
            raise

    def get_team_access(self, team, group, policy_name, ap_name):
        access_point = self.get_access_point(ap_name)
        ap_response = self._call("get access point policy", self.s3control.get_access_point_policy, AccountId=self.settings.aws_account_id, Name=ap_name)
        bucket_response = self._call("get bucket policy", self.s3.get_bucket_policy, Bucket=self.settings.s3_bucket)
        bucket_document = json.loads(bucket_response["Policy"])
        sid_prefix = bucket_policy_sid_prefix(team)
        statements = bucket_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        bucket_document["Statement"] = [statement for statement in statements if statement.get("Sid") in {f"{sid_prefix}List", f"{sid_prefix}Objects"}]
        return {
            "access_point": access_point,
            "iam_policy": self.get_iam_policy_document(policy_name),
            "access_point_policy": json.loads(ap_response["Policy"]),
            "bucket_policy": bucket_document,
        }
