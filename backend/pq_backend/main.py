from __future__ import annotations

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from .audit import audit, export_jsonl
from .auth import current_user, hash_password, require_roles, token, verify_password
from .config import ADMIN_PASSWORD, CORS_ORIGINS
from .db import connect, migrate
from .kem import capabilities, create_kem, encapsulate, decapsulate, rotate_kem, destroy_key

app = FastAPI(title="POST-QUANTAM hardened API", version="0.5.0")
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True, allow_methods=["GET","POST"], allow_headers=["Authorization","Content-Type","X-Request-ID"])

class Login(BaseModel): username: str = Field(min_length=1, max_length=128); password: str = Field(min_length=1, max_length=256)
class KEMRequest(BaseModel): algorithm: str = Field(default="ML-KEM-768", pattern=r"^[A-Za-z0-9._-]{3,64}$")
class KeyRequest(BaseModel): key_id: str
class DecapRequest(BaseModel): key_id: str; ciphertext: str
class DestroyRequest(BaseModel): reason: str = Field(min_length=3, max_length=500)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request); response.headers["X-Content-Type-Options"]="nosniff"; response.headers["X-Frame-Options"]="DENY"; response.headers["Referrer-Policy"]="no-referrer"; return response
@app.on_event("startup")
def startup():
    migrate()
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE username=?", ("admin",)).fetchone(): conn.execute("INSERT INTO users(id,username,password_hash,role,disabled,created_at) VALUES(?,?,?,?,?,datetime('now'))", ("admin","admin",hash_password(ADMIN_PASSWORD),"admin",0))
@app.get("/healthz")
def health(): return {"status":"ok"}
@app.post("/auth/login")
def login(body: Login):
    with connect() as conn: row=conn.execute("SELECT username,password_hash,role,disabled FROM users WHERE username=?",(body.username,)).fetchone()
    if not row or row[3] or not verify_password(body.password,row[1]): raise HTTPException(401,"Invalid credentials")
    audit("login",row[0],None,{}); return {"access_token":token(row[0],row[2]),"token_type":"bearer","role":row[2]}
@app.get("/v1/capabilities")
def caps(user=Depends(current_user)): return capabilities()
@app.post("/v1/kem/keys")
def kem_key(body: KEMRequest,user=Depends(require_roles("admin","operator"))):
    try: return create_kem(body.algorithm,user["username"])
    except (RuntimeError,ValueError) as exc: raise HTTPException(400,str(exc)) from exc
@app.post("/v1/kem/encapsulate")
def kem_enc(body: KeyRequest,user=Depends(require_roles("admin","operator"))):
    try: return encapsulate(body.key_id,user["username"])
    except (RuntimeError,ValueError) as exc: raise HTTPException(400,str(exc)) from exc
@app.post("/v1/kem/decapsulate")
def kem_dec(body: DecapRequest,user=Depends(require_roles("admin","operator"))):
    try: return decapsulate(body.key_id,body.ciphertext,user["username"])
    except (RuntimeError,ValueError,Exception) as exc: raise HTTPException(400,"KEM decapsulation failed") from exc
@app.post("/v1/kem/{key_id}/rotate")
def kem_rotate(key_id: str,user=Depends(require_roles("admin","operator"))):
    try: return rotate_kem(key_id,user["username"])
    except (RuntimeError,ValueError) as exc: raise HTTPException(400,str(exc)) from exc
@app.post("/v1/kem/{key_id}/destroy")
def kem_destroy(key_id: str,body: DestroyRequest,user=Depends(require_roles("admin"))):
    try: return destroy_key(key_id,user["username"],body.reason)
    except ValueError as exc: raise HTTPException(400,str(exc)) from exc
@app.get("/v1/audit.jsonl",response_class=PlainTextResponse)
def audit_export(user=Depends(require_roles("admin","auditor"))): return export_jsonl()
