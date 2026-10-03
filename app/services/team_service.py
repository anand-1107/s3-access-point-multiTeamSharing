import logging
from app.aws_manager import AwsManager
from app.policy_generator import generate_iam_policy, generate_access_point_policy, generate_bucket_policy, resource_names

logger = logging.getLogger(__name__)


class TeamService:
    """Orchestrates desired config; dry-run state remains process-local."""
    def __init__(self, settings, aws_manager=None):
        self.settings = settings
        self.aws = aws_manager
        self.records = {}
        self.user_service = None

    def _manager(self):
        if self.aws is None:
            self.aws = AwsManager(self.settings)
        return self.aws

    def configure(self, request):
        group, ap_name, policy_name = resource_names(request.team)
        ap_arn = f"arn:aws:s3:{self.settings.aws_region}:{self.settings.aws_account_id}:accesspoint/{ap_name}"
        iam = generate_iam_policy(request.team, request.prefix, request.permissions, ap_arn, self.settings.s3_bucket)
        ap_policy = generate_access_point_policy(request.team, request.prefix, request.permissions, ap_arn, self.settings.aws_account_id)
        bucket_policy = generate_bucket_policy(request.team, request.prefix, request.permissions, self.settings.s3_bucket, ap_arn, self.settings.aws_account_id)
        resources = {"iam_policy": iam, "access_point_policy": ap_policy, "bucket_policy": bucket_policy,
                     "iam_group": group, "iam_policy_name": policy_name,
                     "access_point": {"name": ap_name, "bucket": self.settings.s3_bucket, "region": self.settings.aws_region, "arn": ap_arn}}
        logger.info("configure team=%s dry_run=%s", request.team, self.settings.dry_run)
        status = "dry_run"
        if not self.settings.dry_run:
            aws = self._manager()
            aws.ensure_group(group)
            aws.ensure_iam_policy(policy_name, group, iam)
            aws.ensure_access_point(ap_name, self.settings.s3_bucket)
            aws.set_access_point_policy(ap_name, ap_policy)
            resources["bucket_policy"] = aws.reconcile_bucket_policy(bucket_policy, request.team)
            status = "configured"
        record = {"team": request.team, "prefix": request.prefix, "permissions": request.permissions,
                  "iam_group": group, "access_point": ap_name, "access_point_arn": ap_arn, "status": status}
        self.records[request.team] = record
        return {"status": status, **{k: request.model_dump()[k] for k in ("team", "prefix", "permissions")}, "resources": resources}

    def list_teams(self):
        return list(self.records.values())

    def get_team(self, team, *, read_aws=False):
        if team in self.records:
            return self.records[team]
        if self.settings.dry_run and not read_aws:
            return None
        return self._discover(team)

    def _discover(self, team):
        group, ap_name, _ = resource_names(team)
        config = self._manager().current_configuration(team, ap_name)
        if not config:
            return None

        policy = config["access_point_policy"]
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        expected_ap_arn = (
            f"arn:aws:s3:{self.settings.aws_region}:"
            f"{self.settings.aws_account_id}:accesspoint/{ap_name}"
        )

        actions = set()
        prefix = None

        for statement in statements:
            resource = statement.get("Resource", "")
            statement_actions = statement.get("Action", [])

            if isinstance(statement_actions, str):
                statement_actions = [statement_actions]

            # Only inspect statements belonging to this team's Access Point.
            if expected_ap_arn not in resource:
                continue

            actions.update(action for action in statement_actions if action)

            # The object resource identifies the team's S3 prefix.
            if "/object/" in resource:
                path = resource.split("/object/", 1)[1]

                if path.endswith("*"):
                    path = path[:-1]

                path = path.rstrip("/")

                if path:
                    prefix = f"{path}/"

        if prefix is None:
            return None

        permissions = []

        if "s3:GetObject" in actions or "s3:ListBucket" in actions:
            permissions.append("read")

        if "s3:PutObject" in actions:
            permissions.append("write")

        if "s3:DeleteObject" in actions:
            permissions.append("delete")

        record = {
            "team": team,
            "prefix": prefix,
            "permissions": permissions,
            "iam_group": group,
            "access_point": ap_name,
            "access_point_arn": config["access_point"]["AccessPointArn"],
            "status": "configured",
        }

        self.records[team] = record
        return record

    def access(self, team):
        record = self.get_team(team)
        if not record:
            return None
        group, ap_name, policy_name = resource_names(team)
        ap_arn = record["access_point_arn"]
        generated = {
            "iam_policy": generate_iam_policy(team, record["prefix"], record["permissions"], ap_arn, self.settings.s3_bucket),
            "access_point_policy": generate_access_point_policy(team, record["prefix"], record["permissions"], ap_arn, self.settings.aws_account_id),
            "bucket_policy": generate_bucket_policy(team, record["prefix"], record["permissions"], self.settings.s3_bucket, ap_arn),
        }
        access_point = {"name": ap_name, "arn": ap_arn, "bucket": self.settings.s3_bucket, "region": self.settings.aws_region}
        if not self.settings.dry_run:
            actual = self._manager().get_team_access(team, group, policy_name, ap_name)
            access_point.update({"name": ap_name, "arn": actual["access_point"].get("AccessPointArn", ap_arn), "bucket": actual["access_point"].get("Bucket", self.settings.s3_bucket)})
            generated = {"iam_policy": actual["iam_policy"], "access_point_policy": actual["access_point_policy"], "bucket_policy": actual["bucket_policy"]}
        return {"team": team, "iam_group": group, "iam_policy_name": policy_name, "access_point": access_point,
                **generated, "status": record["status"]}

    def delete(self, team):
        record = self.get_team(team)
        if record is None:
            raise LookupError("Team configuration not found")
        group, ap_name, policy_name = resource_names(team)
        generated = generate_bucket_policy(team, record["prefix"], record["permissions"], self.settings.s3_bucket,
                                           f"arn:aws:s3:{self.settings.aws_region}:{self.settings.aws_account_id}:accesspoint/{ap_name}")
        members = []
        if self.settings.dry_run:
            if self.user_service:
                members = [user["username"] for user in self.user_service.list_users() if user["team"] == team]
        else:
            members = self._manager().group_members(group)
        if members:
            raise PermissionError(f"Cannot remove team '{team}' while IAM group '{group}' still has users")
        if not self.settings.dry_run:
            self._manager().delete_team_resources(team, group, policy_name, ap_name, generated)
        self.records.pop(team, None)
        return {"status": "dry_run" if self.settings.dry_run else "deleted", "team": team}
