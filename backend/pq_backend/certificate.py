from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .audit import audit, now
from .config import CA_STATE_PATH
from .crypto import seal, unseal
from .db import connect


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _load_ca() -> tuple[object, x509.Certificate]:
    """Load or create a durable development CA protected by the application master key."""
    CA_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if CA_STATE_PATH.exists():
        state = json.loads(CA_STATE_PATH.read_text())
        private = serialization.load_pem_private_key(unseal(state["private_key"].encode()), password=None)
        certificate = x509.load_pem_x509_certificate(state["certificate"].encode())
        return private, certificate

    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now_dt = _utc()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "POST-QUANTAM Development CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_dt - timedelta(minutes=1))
        .not_valid_after(now_dt + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private, hashes.SHA256())
    )
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    CA_STATE_PATH.write_text(json.dumps({"private_key": seal(private_pem).decode(), "certificate": certificate_pem}))
    try:
        CA_STATE_PATH.chmod(0o600)
    except OSError:
        pass
    return private, certificate


def issue_certificate(subject: str, days: int, actor: str, rotated_from: str | None = None) -> dict:
    if not subject or len(subject) > 255:
        raise ValueError("subject must be 1-255 characters")
    if not 1 <= days <= 3650:
        raise ValueError("days must be between 1 and 3650")

    ca_key, ca_cert = _load_ca()
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    before = _utc() - timedelta(minutes=1)
    after = before + timedelta(days=days)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    leaf_private = leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    key_id, cert_id = str(uuid.uuid4()), str(uuid.uuid4())

    with connect() as conn:
        conn.execute("INSERT INTO keys(id,purpose,algorithm,public_key,encrypted_private_key,state,created_at,rotated_at,revoked_at,destroyed_at,destruction_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (key_id, "certificate", "RSA-3072", cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo), seal(leaf_private), "active", now(), None, None, None, None))
        conn.execute("INSERT INTO certificates(id,key_id,subject,serial_number,pem,not_before,not_after,state,created_at,rotated_from,revoked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (cert_id, key_id, subject, str(cert.serial_number), cert_pem, before.isoformat(), after.isoformat(), "active", now(), rotated_from, None))
    audit("certificate_issued", actor, cert_id, {"subject": subject, "serial_number": str(cert.serial_number), "issuer": ca_cert.subject.rfc4514_string()})
    return {"certificate_id": cert_id, "key_id": key_id, "subject": subject, "issuer": ca_cert.subject.rfc4514_string(), "serial_number": str(cert.serial_number), "not_before": before.isoformat(), "not_after": after.isoformat(), "pem": cert_pem, "pqc_note": "RSA certificate signed by the persisted development CA; this is not a PQC certificate."}


def list_certificates() -> list[dict]:
    threshold = _utc() + timedelta(days=30)
    with connect() as conn:
        rows = conn.execute("SELECT id,key_id,subject,serial_number,not_before,not_after,state,created_at,rotated_from,revoked_at FROM certificates ORDER BY created_at DESC").fetchall()
    return [{**dict(row), "rotation_due": row["state"] == "active" and datetime.fromisoformat(row["not_after"]) <= threshold} for row in rows]


def rotate_certificate(cert_id: str, actor: str) -> dict:
    with connect() as conn:
        row = conn.execute("SELECT subject,key_id,state FROM certificates WHERE id=?", (cert_id,)).fetchone()
    if not row or row["state"] != "active":
        raise ValueError("Active certificate not found")
    replacement = issue_certificate(row["subject"], 365, actor, cert_id)
    with connect() as conn:
        conn.execute("UPDATE certificates SET state='rotated' WHERE id=?", (cert_id,))
        conn.execute("UPDATE keys SET state='retired',rotated_at=? WHERE id=?", (now(), row["key_id"]))
    audit("certificate_rotated", actor, cert_id, {"replacement_certificate_id": replacement["certificate_id"]})
    return {**replacement, "rotated_from": cert_id}


def revoke_certificate(cert_id: str, actor: str) -> dict:
    with connect() as conn:
        row = conn.execute("SELECT key_id,state FROM certificates WHERE id=?", (cert_id,)).fetchone()
    if not row:
        raise ValueError("Certificate not found")
    if row["state"] != "active":
        raise ValueError("Only active certificates can be revoked")
    revoked = now()
    with connect() as conn:
        conn.execute("UPDATE certificates SET state='revoked',revoked_at=? WHERE id=?", (revoked, cert_id))
        conn.execute("UPDATE keys SET state='revoked',revoked_at=? WHERE id=?", (revoked, row["key_id"]))
    audit("certificate_revoked", actor, cert_id, {"revoked_at": revoked})
    return {"certificate_id": cert_id, "key_id": row["key_id"], "state": "revoked", "revoked_at": revoked}


def build_crl() -> str:
    ca_key, ca_cert = _load_ca()
    now_dt = _utc()
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca_cert.subject).last_update(now_dt).next_update(now_dt + timedelta(days=1))
    with connect() as conn:
        rows = conn.execute("SELECT serial_number,revoked_at FROM certificates WHERE state='revoked' AND revoked_at IS NOT NULL").fetchall()
    for row in rows:
        builder = builder.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(int(row["serial_number"])).revocation_date(datetime.fromisoformat(row["revoked_at"])).build())
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
