import pytest
from pydantic import ValidationError
from app.models import TeamConfig


def test_valid_team_request():
    body = TeamConfig(team="research", prefix="research/", permissions=["read", "write"])
    assert body.team == "research"


@pytest.mark.parametrize("permissions", [["admin"], ["read", "s3:PutObject"], []])
def test_invalid_permissions_rejected(permissions):
    with pytest.raises(ValidationError):
        TeamConfig(team="research", prefix="research/", permissions=permissions)


@pytest.mark.parametrize("team", ["", "Finance", "../x", "team_name", "1team"])
def test_invalid_team_names(team):
    with pytest.raises(ValidationError):
        TeamConfig(team=team, prefix="research/", permissions=["read"])


@pytest.mark.parametrize("prefix", ["", "research", "/research/", "../", "research/*", "finance/"])
def test_invalid_prefix(prefix):
    with pytest.raises(ValidationError):
        TeamConfig(team="research", prefix=prefix, permissions=["read"])


def test_access_check_request_validates_operation_and_prefix():
    from app.models import AccessCheckRequest

    assert AccessCheckRequest(username="finance-user", prefix="finance/", operation="read").operation == "read"
    with pytest.raises(ValidationError):
        AccessCheckRequest(username="finance-user", prefix="finance/", operation="list")
