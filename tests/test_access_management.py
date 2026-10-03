import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import app
from app.services.team_service import TeamService
from app.services.user_service import UserService


class ReadOnlyAwsStub:
    def iam_user_exists(self, username):
        return False

    def user_group_names(self, username):
        return []


@pytest.fixture
def client():
    settings = Settings(dry_run=True)
    team_service = TeamService(settings)
    user_service = UserService(settings, aws_manager=ReadOnlyAwsStub(), team_service=team_service)
    team_service.user_service = user_service
    app.state.team_service = team_service
    app.state.user_service = user_service
    return TestClient(app)


def add_team(client, team):
    response = client.post("/s3-access/add-team", json={"team": team, "prefix": f"{team}/", "permissions": ["read", "write"]})
    assert response.status_code == 200
    return response.json()


def test_add_team_is_idempotent_and_iam_policy_references_team_ap(client):
    first = add_team(client, "research")
    second = add_team(client, "research")
    assert first["resources"]["iam_policy"] == second["resources"]["iam_policy"]
    policy = second["resources"]["iam_policy"]
    assert any("research-ap" in statement["Resource"] for statement in policy["Statement"])


def test_get_team_returns_definition_and_get_team_access_returns_policies(client):
    add_team(client, "research")
    team = client.get("/s3-access/get-team/research").json()
    access = client.get("/s3-access/get-team-access/research").json()
    assert team["team"] == "research"
    assert team["status"] == "dry_run"
    assert len(client.get("/s3-access/list-teams").json()["teams"]) == 1
    assert "resources" not in team
    assert "iam_policy" not in team
    assert access["iam_group"] == "ResearchGroup"
    assert access["iam_policy_name"] == "ResearchPolicy"
    assert access["access_point"]["arn"].endswith("accesspoint/research-ap")
    assert "Statement" in access["iam_policy"]
    assert "Statement" in access["access_point_policy"]
    assert "Statement" in access["bucket_policy"]
    assert access["status"] == "dry_run"


def test_user_must_target_existing_team_and_multiple_users_share_group(client):
    missing = client.post("/s3-access/add-user", json={"username": "research-user", "team": "research"})
    assert missing.status_code == 404
    add_team(client, "research")
    for username in ("research-user", "research-user2"):
        response = client.post("/s3-access/add-user", json={"username": username, "team": "research"})
        assert response.status_code == 200
        assert response.json()["iam_group"] == "ResearchGroup"


def test_update_get_and_list_users(client):
    add_team(client, "research")
    add_team(client, "finance")
    missing = client.put("/s3-access/update-user", json={"username": "unknown-user", "team": "finance"})
    assert missing.status_code == 404
    client.post("/s3-access/add-user", json={"username": "research-user", "team": "research"})
    changed = client.put("/s3-access/update-user", json={"username": "research-user", "team": "finance"})
    assert changed.status_code == 200
    assert changed.json()["iam_group"] == "FinanceGroup"
    assert client.get("/s3-access/get-user/research-user").json()["team"] == "finance"
    assert client.get("/s3-access/list-users").json()["users"] == [changed.json()]


def test_team_removal_conflicts_while_users_remain(client):
    add_team(client, "research")
    client.post("/s3-access/add-user", json={"username": "research-user", "team": "research"})
    response = client.delete("/s3-access/remove-team/research")
    assert response.status_code == 409


def test_access_check_grants_matching_team_prefix_and_permission(client):
    add_team(client, "finance")
    client.post("/s3-access/add-user", json={"username": "finance-user", "team": "finance"})
    response = client.post("/s3-access/check-access", json={"username": "finance-user", "prefix": "finance/", "operation": "read"})
    assert response.status_code == 200
    assert response.json() == {
        "allowed": True,
        "message": "Access granted",
        "username": "finance-user",
        "team": "finance",
        "requested_prefix": "finance/",
        "configured_prefix": "finance/",
        "operation": "read",
        "access_point": "finance-ap",
    }


def test_access_check_denies_prefix_mismatch(client):
    add_team(client, "finance")
    client.post("/s3-access/add-user", json={"username": "finance-user", "team": "finance"})
    response = client.post("/s3-access/check-access", json={"username": "finance-user", "prefix": "ml/", "operation": "read"})
    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["team"] == "finance"
    assert "outside team" in response.json()["reason"]


def test_access_check_denies_unpermitted_operation(client):
    client.post("/s3-access/add-team", json={"team": "finance", "prefix": "finance/", "permissions": ["read", "write"]})
    client.post("/s3-access/add-user", json={"username": "finance-user", "team": "finance"})
    response = client.post("/s3-access/check-access", json={"username": "finance-user", "prefix": "finance/", "operation": "delete"})
    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert response.json()["reason"] == "Operation 'delete' is not permitted for team 'finance'"


def test_access_check_returns_404_for_unknown_user(client):
    response = client.post("/s3-access/check-access", json={"username": "missing-user", "prefix": "finance/", "operation": "read"})
    assert response.status_code == 404
    assert "does not exist" in response.json()["detail"]


def test_access_check_denies_user_without_configured_team(client):
    client.app.state.user_service.records["orphan-user"] = {"username": "orphan-user", "team": "ghost", "iam_group": "GhostGroup", "status": "dry_run"}
    response = client.post("/s3-access/check-access", json={"username": "orphan-user", "prefix": "ghost/", "operation": "read"})
    assert response.status_code == 200
    assert response.json()["allowed"] is False
    assert "does not belong to a configured team" in response.json()["reason"]


def test_access_check_uses_aws_group_membership_for_existing_user():
    settings = Settings(dry_run=False)
    team_service = TeamService(settings)
    team_service.records["finance"] = {
        "team": "finance", "prefix": "finance/", "permissions": ["read"],
        "iam_group": "FinanceGroup", "access_point": "finance-ap",
        "access_point_arn": "arn:aws:s3:ap-south-1:618046392939:accesspoint/finance-ap",
        "status": "configured",
    }

    class ExistingUserAwsStub:
        def iam_user_exists(self, username):
            return username == "finance-user"

        def user_group_names(self, username):
            return ["FinanceGroup"]

    user_service = UserService(settings, aws_manager=ExistingUserAwsStub(), team_service=team_service)
    from app.models import AccessCheckRequest

    result = user_service.check_access(AccessCheckRequest(username="finance-user", prefix="finance/", operation="read"))
    assert result["allowed"] is True
    assert result["team"] == "finance"


def test_existing_aws_user_without_team_group_is_denied():
    settings = Settings(dry_run=False)
    team_service = TeamService(settings)

    class ExistingUserWithoutGroups:
        def iam_user_exists(self, username):
            return True

        def user_group_names(self, username):
            return []

    user_service = UserService(settings, aws_manager=ExistingUserWithoutGroups(), team_service=team_service)
    from app.models import AccessCheckRequest

    result = user_service.check_access(AccessCheckRequest(username="orphan-user", prefix="finance/", operation="read"))
    assert result["allowed"] is False
    assert "does not belong to a configured team" in result["reason"]
