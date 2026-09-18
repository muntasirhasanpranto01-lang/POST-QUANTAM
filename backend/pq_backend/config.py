from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.getenv("PQ_DATA_DIR", "./data"))
ROOT.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.getenv("PQ_DATABASE", str(ROOT / "post_quantam.sqlite3")))
AUTH_SECRET = os.getenv("PQ_AUTH_SECRET", "development-only-change-me")
MASTER_KEY = os.getenv("PQ_MASTER_KEY")
ADMIN_PASSWORD = os.getenv("PQ_ADMIN_PASSWORD", "change-me")
JWT_MINUTES = int(os.getenv("PQ_JWT_MINUTES", "30"))

if not MASTER_KEY:
    from cryptography.fernet import Fernet
    MASTER_KEY = Fernet.generate_key().decode()
