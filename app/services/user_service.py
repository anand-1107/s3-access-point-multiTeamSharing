import logging
import re
from app.policy_generator import resource_names
from app.aws_manager import AwsManager

logger = logging.getLogger(__name__)


class UserService:
    """Assigns IAM users to the existing team groups managed by this application."""
    def __init__(self, settings, aws_manager=None, team_service=None):
        self.settings = settings
        self.aws = aws_manager
        self.team_service = team_service
        self.records = {}

    def _manager(self):
        if self.aws is None:
            self.aws = AwsManager(self.settings)
        return self.aws

    def add_or_update(self, request, *, require_existing=False):
        username = request.username
        team = request.team
        group, _, _ = resource_names(team)
        if self.team_service is None or self.team_service.get_team(team) is None:
            raise LookupError(f"Team '{team}' does not exist")
        existing = self.records.get(username)
        if require_existing and existing is None and self.settings.dry_run:
            raise LookupError(f"User '{username}' is not configured")
        status = "dry_run"
        if not self.settings.dry_run:
            aws = self._manager()
            if not aws.group_exists(group):
                raise LookupError(f"Team '{team}' has no existing IAM group")
            if require_existing:
                if not aws.iam_user_exists(username):
                    raise LookupError(f"User '{username}' does not exist")
            else:
                aws.ensure_iam_user(username)
            aws.remove_user_from_other_managed_team_groups(username, group)
            aws.add_user_to_group(username, group)
            status = "configured"
        record = {"username": username, "team": team, "iam_group": group, "status": status}
        self.records[username] = record
        logger.info("assign user=%s team=%s dry_run=%s", username, team, self.settings.dry_run)
        return record

    def get_user(self, username):
        return self.records.get(username)

    def list_users(self):
        return list(self.records.values())

    def remove_user(self, username):
        record = self.records.get(username)
        if record is None:
            raise LookupError("User assignment not found")
        if not self.settings.dry_run:
            group, _, _ = resource_names(record["team"])
            self._manager().remove_user_from_group(username, group)
        del self.records[username]
        return {"status": "dry_run" if self.settings.dry_run else "removed_from_team", "username": username}

    @staticmethod
    def _team_from_group_name(group_name):
        if not group_name.endswith("Group"):
            return None
        title = group_name[:-5]
        if not title:
            return None
        if title == "ML":
            return "ml"
        return re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", title).lower()

    def _configured_user_team(self, username):
        local_user = self.records.get(username)
        if self.settings.dry_run and local_user is not None:
            team_name = local_user.get("team")
            return self.team_service.get_team(team_name) if self.team_service and team_name else None

        # Access verification only performs read-only IAM/S3 lookups in dry-run
        # mode. This lets existing AWS users be checked without changing AWS.
        aws = self._manager()
        if not aws.iam_user_exists(username):
            raise LookupError(f"IAM user '{username}' does not exist")

        group_names = aws.user_group_names(username)
        records = []
        known_teams = {record["team"]: record for record in self.team_service.list_teams()} if self.team_service else {}
        for group_name in group_names:
            record = next((r for r in known_teams.values() if r.get("iam_group") == group_name), None)
            if record is None and self.team_service is not None:
                team_name = self._team_from_group_name(group_name)
                if team_name:
                    record = self.team_service.get_team(team_name, read_aws=True)
            if record and record.get("iam_group") == group_name:
                records.append(record)
        unique = {record["team"]: record for record in records}
        if len(unique) > 1:
            return list(unique.values())
        if unique:
            return next(iter(unique.values()))
        if local_user is not None:
            # Preserve a dry-run assignment when its definition is not currently
            # available, so the decision can explain the missing team configuration.
            return None
        return None

    def check_access(self, request):
        user = self._configured_user_team(request.username)
        if isinstance(user, list):
            return {
                "allowed": False,
                "message": "Access denied",
                "username": request.username,
                "requested_prefix": request.prefix,
                "operation": request.operation,
                "reason": f"User '{request.username}' belongs to multiple configured teams",
            }
        if user is None:
            return {
                "allowed": False,
                "message": "Access denied",
                "username": request.username,
                "requested_prefix": request.prefix,
                "operation": request.operation,
                "reason": f"User '{request.username}' does not belong to a configured team",
            }

        team = user["team"]
        configured_prefix = user["prefix"]
        access_point = user["access_point"]
        response = {
            "allowed": False,
            "message": "Access denied",
            "username": request.username,
            "team": team,
            "requested_prefix": request.prefix,
            "configured_prefix": configured_prefix,
            "operation": request.operation,
            "access_point": access_point,
        }
        if not request.prefix.startswith(configured_prefix):
            response["reason"] = f"Requested prefix '{request.prefix}' is outside team '{team}' prefix '{configured_prefix}'"
            return response
        if request.operation not in user["permissions"]:
            response["reason"] = f"Operation '{request.operation}' is not permitted for team '{team}'"
            return response
        response["allowed"] = True
        response["message"] = "Access granted"
        return response
