from __future__ import annotations

import base64
from cryptography.fernet import Fernet
from .config import MASTER_KEY

_cipher = Fernet(MASTER_KEY.encode() if isinstance(MASTER_KEY, str) else MASTER_KEY)
def seal(value: bytes) -> bytes: return _cipher.encrypt(value)
def unseal(value: bytes) -> bytes: return _cipher.decrypt(value)
def b64(value: bytes) -> str: return base64.b64encode(value).decode("ascii")
def unb64(value: str) -> bytes: return base64.b64decode(value, validate=True)
