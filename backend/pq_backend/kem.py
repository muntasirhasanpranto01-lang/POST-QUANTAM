from __future__ import annotations

import uuid
from .audit import audit, now
from .crypto import b64, seal, unb64, unseal
from .db import connect
try:
    import oqs
except ImportError:
    oqs = None

def capabilities():
    if oqs is None: return {"available": False, "provider": None, "kem_algorithms": [], "signature_algorithms": []}
    return {"available": True, "provider": "liboqs", "kem_algorithms": list(oqs.get_enabled_kem_mechanisms()), "signature_algorithms": list(oqs.get_enabled_sig_mechanisms())}
def _check(algorithm):
    caps = capabilities()
    if not caps["available"]: raise RuntimeError("liboqs is unavailable")
    if algorithm not in caps["kem_algorithms"]: raise ValueError(f"Unsupported KEM algorithm: {algorithm}")
def create_kem(algorithm, actor):
    _check(algorithm)
    with oqs.KeyEncapsulation(algorithm) as kem:
        public = kem.generate_keypair(); private = kem.export_secret_key()
    key_id = str(uuid.uuid4())
    with connect() as conn: conn.execute("INSERT INTO keys(id,purpose,algorithm,public_key,encrypted_private_key,state,created_at) VALUES(?,?,?,?,?,?,?)", (key_id,"kem",algorithm,public,seal(private),"active",now()))
    audit("key_created", actor, key_id, {"algorithm": algorithm})
    return {"key_id": key_id, "algorithm": algorithm, "public_key": b64(public)}
def _active(key_id):
    with connect() as conn: row = conn.execute("SELECT * FROM keys WHERE id=? AND state='active'", (key_id,)).fetchone()
    if not row: raise ValueError("Active key not found")
    return row
def encapsulate(key_id, actor):
    row = _active(key_id); _check(row["algorithm"])
    with oqs.KeyEncapsulation(row["algorithm"]) as kem: ciphertext, secret = kem.encap_secret(bytes(row["public_key"]))
    audit("key_encapsulated", actor, key_id, {"algorithm": row["algorithm"]})
    return {"key_id": key_id, "algorithm": row["algorithm"], "ciphertext": b64(ciphertext), "shared_secret": b64(secret)}
def decapsulate(key_id, ciphertext, actor):
    row = _active(key_id); _check(row["algorithm"])
    with oqs.KeyEncapsulation(row["algorithm"], secret_key=unseal(bytes(row["encrypted_private_key"]))) as kem: secret = kem.decap_secret(unb64(ciphertext))
    audit("key_decapsulated", actor, key_id, {"algorithm": row["algorithm"]})
    return {"key_id": key_id, "algorithm": row["algorithm"], "shared_secret": b64(secret)}
def rotate_kem(key_id, actor):
    row = _active(key_id); replacement = create_kem(row["algorithm"], actor)
    with connect() as conn: conn.execute("UPDATE keys SET state='retired',rotated_at=? WHERE id=?", (now(), key_id))
    audit("key_rotated", actor, key_id, {"replacement_key_id": replacement["key_id"]}); return replacement
def destroy_key(key_id, actor, reason):
    row = _active(key_id)
    with connect() as conn: conn.execute("UPDATE keys SET state='destroyed',encrypted_private_key=?,destroyed_at=?,destruction_reason=? WHERE id=?", (b"",now(),reason,key_id))
    audit("key_destroyed", actor, key_id, {"reason": reason}); return {"key_id": key_id, "state": "destroyed"}
