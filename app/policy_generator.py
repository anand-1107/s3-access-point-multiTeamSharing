from collections.abc import Sequence

# Keep the high-level permission mapping in one place. Never accept IAM actions from callers.
PERMISSION_ACTIONS: dict[str, tuple[str, ...]] = {
    "read": ("s3:GetObject", "s3:ListBucket"),
    "write": ("s3:PutObject",),
    "delete": ("s3:DeleteObject",),
}
MANAGED_BUCKET_SID_PREFIX = "S3AccessManager"


def bucket_policy_sid_prefix(team: str) -> str:
    return f"{MANAGED_BUCKET_SID_PREFIX}{team.replace(chr(45), chr(95))}"


def actions_for(permissions: Sequence[str]) -> list[str]:
    return sorted({action for permission in permissions for action in PERMISSION_ACTIONS[permission]})


def resource_names(team: str) -> tuple[str, str, str]:
    title = "".join(part.capitalize() for part in team.split("-"))
    if team == "ml":
        title = "ML"
    group = f"{title}Group"
    return group, f"{team}-ap", f"{title}Policy"


def _policy(statements: list[dict]) -> dict:
    return {"Version": "2012-10-17", "Statement": statements}


def generate_iam_policy(team: str, prefix: str, permissions: Sequence[str], access_point_arn: str, bucket_name: str) -> dict:
    statements = []
    actions = actions_for(permissions)
    object_actions = [a for a in actions if a != "s3:ListBucket"]
    if "s3:ListBucket" in actions:
        statements.append({"Sid": "ListTeamPrefixThroughAccessPoint", "Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket_name}", "Condition": {"StringLike": {"s3:prefix": [prefix, f"{prefix}*"]}}})
    if object_actions:
        statements.append({"Sid": "TeamObjectsThroughAccessPoint", "Effect": "Allow", "Action": object_actions, "Resource": f"{access_point_arn}/object/{prefix}*"})
    return _policy(statements)


def generate_access_point_policy(team: str, prefix: str, permissions: Sequence[str], access_point_arn: str, account_id: str) -> dict:
    # IAM group policy controls which signed-in account principals have these actions.
    # The account principal here delegates within the account; it does not independently
    # grant a principal permission absent an identity policy.
    actions = actions_for(permissions)
    statements = []
    object_actions = [a for a in actions if a != "s3:ListBucket"]
    if "s3:ListBucket" in actions:
        statements.append({"Sid": "AllowAccountListTeamPrefix", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "s3:ListBucket", "Resource": access_point_arn, "Condition": {"StringLike": {"s3:prefix": [prefix, f"{prefix}*"]}}})
    if object_actions:
        statements.append({"Sid": "AllowAccountTeamObjects", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": object_actions, "Resource": f"{access_point_arn}/object/{prefix}*"})
    return _policy(statements)


def generate_bucket_policy(team: str, prefix: str, permissions: Sequence[str], bucket_name: str, access_point_arn: str | None = None, account_id: str | None = None) -> dict:
    """Return only this team's bucket-policy delegation statements for review/merge.

    The caller should pass the exact access point ARN. The optional default keeps the
    function signature convenient for dry-run generation when ARN is not yet known.
    """
    ap_arn = access_point_arn or f"arn:aws:s3:REGION:ACCOUNT:accesspoint/{team}-ap"
    actions = actions_for(permissions)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    statements = []
    if "s3:ListBucket" in actions:
        statements.append({"Sid": f"{bucket_policy_sid_prefix(team)}List", "Effect": "Allow", "Principal": "*", "Action": "s3:ListBucket", "Resource": bucket_arn, "Condition": {"StringEquals": {"s3:DataAccessPointArn": ap_arn}, "StringLike": {"s3:prefix": [prefix, f"{prefix}*"]}}})
    object_actions = [a for a in actions if a != "s3:ListBucket"]
    if object_actions:
        statements.append({"Sid": f"{bucket_policy_sid_prefix(team)}Objects", "Effect": "Allow", "Principal": "*", "Action": object_actions, "Resource": f"{bucket_arn}/{prefix}*", "Condition": {"StringEquals": {"s3:DataAccessPointArn": ap_arn}}})
    return _policy(statements)
