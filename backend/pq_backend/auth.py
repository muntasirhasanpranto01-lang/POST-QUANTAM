from __future__ import annotations

from datetime import datetime, timedelta, timezone
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from .config import AUTH_SECRET, JWT_MINUTES
from .db import connect

passwords = PasswordHash.recommended()
bearer = HTTPBearer(auto_error=False)

def hash_password(value: str) -> str: return passwords.hash(value)
def verify_password(value: str, hashed: str) -> bool: return passwords.verify(value, hashed)

def token(username: str, role: str) -> str:
    return jwt.encode({"sub": username, "role": role, "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_MINUTES)}, AUTH_SECRET, algorithm="HS256")

def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if not credentials: raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    try: payload = jwt.decode(credentials.credentials, AUTH_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as exc: raise HTTPException(status_code=401, detail="Invalid token") from exc
    with connect() as conn: row = conn.execute("SELECT username,role,disabled FROM users WHERE username=?", (payload.get("sub"),)).fetchone()
    if not row or row[2]: raise HTTPException(status_code=401, detail="User unavailable")
    return {"username": row[0], "role": row[1]}

def require_roles(*roles: str):
    def dependency(user: dict = Depends(current_user)):
        if user["role"] not in roles: raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return dependency
