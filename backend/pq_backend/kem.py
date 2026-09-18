from __future__ import annotations

try:
    import oqs
except ImportError:
    oqs = None

from .crypto import b64, seal, unseal, unb64
from .db import connect
from .audit import audit, now
import uuid

def capabilities():
    if oqs is None: return {"available": False, "provider": None, "kem_algorithms": [], "signature_algorithms": []}
    return {"available": True, "provider": "liboqs", "kem_algorithms": list(oqs.get_enabled_kem_mechanisms()), "signature_algorithms": list(oqs.get_enabled_sig_mechanisms())}

def create_kem(algorithm: str, actor: str):
    caps = capabilities()
    if not caps["available"]: raise RuntimeError("liboqs unavailable")
    if algorithm not in caps["kem_algorithms"]: raise ValueError("Unsupported KEM")
    with oqs.KeyEncapsulation(algorithm) as kem:
        public, private = kem.generate_keypair(), kem.export_secret_key()
    key_id = str(uuid.uuid4())
    with connect() as conn: conn.execute("INSERT INTO keys VALUES(?,?,?,?,?,?,?,?,?,?)", (key_id,"kem",algorithm,public,seal(private),"active",now(),None,None,None))
    audit("key_created", actor, key_id, {"algorithm": algorithm})
    return {"key_id": key_id, "algorithm": algorithm, "public_key": b64(public)}

def encapsulate(key_id: str, actor: str):
    with connect() as conn: row = conn.execute("SELECT * FROM keys WHERE id=? AND state='active'", (key_id,)).fetchone()
    if not row: raise ValueError("Active key not found")
    if oqs is None: raise RuntimeError("liboqs unavailable")
    with oqs.KeyEncapsulation(row[2]) as kem: ciphertext, secret = kem.encap_secret(bytes(row[3]))
    audit("key_encapsulated", actor, key_id, {"algorithm": row[2]})
    return {"key_id": key_id, "ciphertext": b64(ciphertext), "shared_secret": b64(secret), "demo_warning": "Do not expose shared secrets in production"}

def decapsulate(key_id: str, ciphertext: str, actor: str):
    with connect() as conn: row = conn.execute("SELECT * FROM keys WHERE id=? AND state='active'", (key_id,)).fetchone()
    if not row: raise ValueError("Active key not found")
    if oqs is None: raise RuntimeError("liboqs unavailable")
    with oqs.KeyEncapsulation(row[2], secret_key=unseal(bytes(row[4]))) as kem: secret = kem.decap_secret(unb64(ciphertext))
    audit("key_decapsulated", actor, key_id, {"algorithm": row[2]})
    return {"key_id": key_id, "shared_secret": b64(secret), "demo_warning": "Do not expose shared secrets in production"}
