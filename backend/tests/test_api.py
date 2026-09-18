import pytest
from fastapi.testclient import TestClient
from pq_backend.main import app
from pq_backend import kem

@pytest.fixture()
def client(tmp_path, monkeypatch):
    import pq_backend.config as config
    import pq_backend.db as db
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr(config, "CA_STATE_PATH", tmp_path / "ca-state.json")
    with TestClient(app) as test_client:
        yield test_client

def auth(client):
    response = client.post("/auth/login", json={"username": "admin", "password": "change-me"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}

def test_auth_and_certificate_lifecycle(client):
    headers = auth(client)
    issued = client.post("/v1/pki/certificates", headers=headers, json={"subject": "test.internal", "days": 30})
    assert issued.status_code == 200
    cert_id = issued.json()["certificate_id"]
    assert "BEGIN CERTIFICATE" in issued.json()["pem"]
    listed = client.get("/v1/pki/certificates", headers=headers)
    assert listed.status_code == 200
    rotated = client.post(f"/v1/pki/certificates/{cert_id}/rotate", headers=headers)
    assert rotated.status_code == 200
    revoked = client.post(f"/v1/pki/certificates/{rotated.json()['certificate_id']}/revoke", headers=headers)
    assert revoked.status_code == 200
    crl = client.get("/v1/pki/crl.pem", headers=headers)
    assert crl.status_code == 200 and "BEGIN X509 CRL" in crl.text

def test_real_liboqs_round_trip_if_available(client):
    if not kem.capabilities()["available"]:
        pytest.skip("liboqs unavailable")
    headers = auth(client)
    algorithm = kem.capabilities()["kem_algorithms"][0]
    created = client.post("/v1/kem/keys", headers=headers, json={"algorithm": algorithm})
    assert created.status_code == 200
    key_id = created.json()["key_id"]
    encapsulated = client.post("/v1/kem/encapsulate", headers=headers, json={"key_id": key_id})
    assert encapsulated.status_code == 200
    decapsulated = client.post("/v1/kem/decapsulate", headers=headers, json={"key_id": key_id, "ciphertext": encapsulated.json()["ciphertext"]})
    assert decapsulated.status_code == 200
    assert decapsulated.json()["shared_secret"] == encapsulated.json()["shared_secret"]
