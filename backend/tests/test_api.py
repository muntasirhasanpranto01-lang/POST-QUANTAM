import base64
import pytest
from fastapi.testclient import TestClient
from pq_backend.main import app
from pq_backend import kem

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("pq_backend.config.DB_PATH", tmp_path / "test.sqlite3")
    with TestClient(app) as c: yield c

def auth(client):
    response=client.post("/auth/login",json={"username":"admin","password":"change-me"}); assert response.status_code==200
    return {"Authorization":f"Bearer {response.json()['access_token']}"}

def test_auth_required(client): assert client.get("/v1/capabilities").status_code==401

def test_migration_and_audit(client):
    headers=auth(client); assert client.get("/v1/capabilities",headers=headers).status_code==200; assert client.get("/v1/audit.jsonl",headers=headers).status_code==200

def test_real_liboqs_round_trip_if_available(client):
    if not kem.capabilities()["available"]: pytest.skip("liboqs unavailable")
    headers=auth(client); created=client.post("/v1/kem/keys",headers=headers,json={"algorithm":kem.capabilities()["kem_algorithms"][0]}); assert created.status_code==200
    key_id=created.json()["key_id"]; enc=client.post("/v1/kem/encapsulate",headers=headers,json={"key_id":key_id}); assert enc.status_code==200
    dec=client.post("/v1/kem/decapsulate",headers=headers,json={"key_id":key_id,"ciphertext":enc.json()["ciphertext"]}); assert dec.status_code==200
    assert dec.json()["shared_secret"]==enc.json()["shared_secret"]

def test_destroy_requires_admin(client):
    assert client.get("/healthz").json()["status"]=="ok"
