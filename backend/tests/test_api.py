import pytest
from fastapi.testclient import TestClient
from pq_backend.main import app

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PQ_DATABASE", str(tmp_path / "test.sqlite3"))
    with TestClient(app) as c:
        yield c

def token(client):
    response = client.post("/auth/login", json={"username":"admin", "password":"change-me"})
    assert response.status_code == 200
    return response.json()["access_token"]

def test_login_and_health(client):
    assert client.get("/healthz").status_code == 200
    assert token(client)

def test_auth_required(client):
    assert client.get("/v1/capabilities").status_code == 401

def test_certificate_lifecycle(client):
    auth = {"Authorization": f"Bearer {token(client)}"}
    issued = client.post("/v1/pki/certificates", headers=auth, json={"subject":"test.internal","days":30})
    assert issued.status_code == 200
    cid = issued.json()["certificate_id"]
    revoked = client.post(f"/v1/pki/certificates/{cid}/revoke", headers=auth)
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoked"
