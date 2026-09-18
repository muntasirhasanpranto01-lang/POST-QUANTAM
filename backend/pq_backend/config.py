from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet

DATA_DIR = Path(os.getenv("PQ_DATA_DIR", "./data"))
DB_PATH = Path(os.getenv("PQ_DATABASE", str(DATA_DIR / "post_quantam.sqlite3")))
AUTH_SECRET = os.getenv("PQ_AUTH_SECRET")
MASTER_KEY = os.getenv("PQ_MASTER_KEY")
ADMIN_PASSWORD = os.getenv("PQ_ADMIN_PASSWORD")
JWT_MINUTES = int(os.getenv("PQ_JWT_MINUTES", "30"))
CORS_ORIGINS = [x.strip() for x in os.getenv("PQ_CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]

if not AUTH_SECRET or not MASTER_KEY or not ADMIN_PASSWORD:
    if os.getenv("PQ_ENV", "development") == "production":
        raise RuntimeError("PQ_AUTH_SECRET, PQ_MASTER_KEY, and PQ_ADMIN_PASSWORD are required in production")
    AUTH_SECRET = AUTH_SECRET or "development-auth-secret-change-me"
    ADMIN_PASSWORD = ADMIN_PASSWORD or "change-me"
    MASTER_KEY = MASTER_KEY or Fernet.generate_key().decode()
