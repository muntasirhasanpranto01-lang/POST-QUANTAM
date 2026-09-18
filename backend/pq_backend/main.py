from __future__ import annotations

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from .db import migrate, connect
from .config import ADMIN_PASSWORD
from .auth import hash_password, verify_password, token, current_user, require_roles
from .audit import audit, export_jsonl
from .kem import capabilities, create_kem, encapsulate, decapsulate
from .certificate import issue_certificate, rotate_certificate, revoke_certificate, list_certificates, build_crl

app = FastAPI(title="POST-QUANTAM hardened API", version="0.4.0")

class Login(BaseModel): username: str; password: str
class KEMRequest(BaseModel): algorithm: str = "ML-KEM-768"
class KeyRequest(BaseModel): key_id: str
class DecapRequest(BaseModel): key_id: str; ciphertext: str
class CertRequest(BaseModel): subject: str = Field(min_length=1, max_length=255); days: int = Field(365, ge=1, le=3650)

@app.on_event("startup")
def startup():
    migrate()
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            conn.execute("INSERT INTO users VALUES(?,?,?,?,?)", ("admin", "admin", hash_password(ADMIN_PASSWORD), "admin", 0,))

@app.get("/healthz")
def health(): return {"status": "ok"}
@app.post("/auth/login")
def login(body: Login):
    with connect() as conn: row = conn.execute("SELECT username,password_hash,role,disabled FROM users WHERE username=?", (body.username,)).fetchone()
    if not row or row[3] or not verify_password(body.password, row[1]): raise HTTPException(401, "Invalid credentials")
    audit("login", row[0], None, {})
    return {"access_token": token(row[0], row[2]), "token_type": "bearer", "role": row[2]}

@app.get("/v1/capabilities")
def caps(_: dict = Depends(current_user)): return capabilities()
@app.post("/v1/kem/keys")
def kem_key(body: KEMRequest, user=Depends(require_roles("admin", "operator"))):
    try: return create_kem(body.algorithm, user["username"])
    except (RuntimeError, ValueError) as exc: raise HTTPException(400, str(exc)) from exc
@app.post("/v1/kem/encapsulate")
def kem_enc(body: KeyRequest, user=Depends(require_roles("admin", "operator"))):
    try: return encapsulate(body.key_id, user["username"])
    except (RuntimeError, ValueError) as exc: raise HTTPException(400, str(exc)) from exc
@app.post("/v1/kem/decapsulate")
def kem_dec(body: DecapRequest, user=Depends(require_roles("admin", "operator"))):
    try: return decapsulate(body.key_id, body.ciphertext, user["username"])
    except (RuntimeError, ValueError) as exc: raise HTTPException(400, str(exc)) from exc

@app.post("/v1/pki/certificates")
def cert_issue(body: CertRequest, user=Depends(require_roles("admin", "operator"))): return issue_certificate(body.subject, body.days, user["username"])
@app.get("/v1/pki/certificates")
def cert_list(_: dict = Depends(current_user)): return list_certificates()
@app.post("/v1/pki/certificates/{cert_id}/rotate")
def cert_rotate(cert_id: str, user=Depends(require_roles("admin", "operator"))): return rotate_certificate(cert_id, user["username"])
@app.post("/v1/pki/certificates/{cert_id}/revoke")
def cert_revoke(cert_id: str, user=Depends(require_roles("admin", "operator"))): return revoke_certificate(cert_id, user["username"])
@app.get("/v1/pki/crl.pem", response_class=PlainTextResponse)
def crl(_: dict = Depends(current_user)): return build_crl()
@app.get("/v1/audit.jsonl", response_class=PlainTextResponse)
def audit_export(_: dict = Depends(require_roles("admin", "auditor"))): return export_jsonl()
