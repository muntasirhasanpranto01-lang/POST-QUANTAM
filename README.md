# POST-QUANTAM

Production-oriented PQC control-plane backend scaffold.

Included:

- SQLite migrations with schema versioning
- JWT authentication and role checks
- Encrypted key metadata and key lifecycle states
- Audit logging with JSONL export
- Certificate issuance, rotation, revocation, and PEM CRL export
- Optional strict liboqs ML-KEM integration
- Tests for auth, migrations, RBAC, and certificate lifecycle

This is not a certification or a replacement for a reviewed CA/KMS/HSM. Set `PQ_AUTH_SECRET` and `PQ_MASTER_KEY` outside development, use TLS, and place production private-key operations behind an HSM/KMS.

## Run

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
export PQ_AUTH_SECRET="change-me-in-a-secret-manager"
export PQ_MASTER_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
uvicorn pq_backend.main:app --reload
pytest
```

Default development user: `admin` / `change-me`; override with `PQ_ADMIN_PASSWORD`.
