from __future__ import annotations

from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from .config import AUTH_SECRET, JWT_MINUTES
from .db import connect

passwords = PasswordHash.recommended(); bearer = HTTPBearer(auto_error=False)
def now(): return datetime.now(timezone.utc)
def hash_password(value): return passwords.hash(value)
def verify_password(value, hashed): return passwords.verify(value, hashed)
def token(username, role): return jwt.encode({"sub": username, "role": role, "exp": now() + timedelta(minutes=JWT_MINUTES)}, AUTH_SECRET, algorithm="HS256")
def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    if not credentials: raise HTTPException(401, "Bearer token required")
    try: payload = jwt.decode(credentials.credentials, AUTH_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as exc: raise HTTPException(401, "Invalid token") from exc
    with connect() as conn: row = conn.execute("SELECT username,role,disabled FROM users WHERE username=?", (payload.get("sub"),)).fetchone()
    if not row or row[2]: raise HTTPException(401, "User unavailable")
    return {"username": row[0], "role": row[1]}
def require_roles(*roles):
    def dependency(user=Depends(current_user)):
        if user["role"] not in roles: raise HTTPException(403, "Insufficient role")
        return user
    return dependency
