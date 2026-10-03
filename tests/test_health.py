from fastapi.testclient import TestClient
from app.main import app


def test_root_and_health():
    client = TestClient(app)
    assert client.get("/").status_code == 200
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_swagger_has_two_operation_groups():
    schema = TestClient(app).get("/openapi.json").json()
    tags = {tag for path in schema["paths"].values() for operation in path.values() for tag in operation.get("tags", [])}
    assert tags == {"Team Operations", "User Operations", "Access Verification"}
