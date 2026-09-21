"""Symmetric encryption for secrets the GDS itself must store at rest --
currently just push-device passwords (gds/push_client.py's
`ConnectionTestResult`/`PushResult` flows, configured via the web UI).

Deliberately separate from gds/pki.py's hybrid_encrypt_for_client: that one
is an asymmetric envelope addressed to an external application's own
keypair, for a one-time handoff it alone can open. This is the opposite
shape -- the GDS encrypts something only the GDS itself will ever decrypt
again, to type a stored device's password back in for a push. A single
Fernet key, generated once and kept next to the CA under the data dir,
covers that.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

__all__ = ["load_or_create_key", "encrypt", "decrypt", "InvalidToken"]


def load_or_create_key(pki_dir: Path) -> bytes:
    pki_dir.mkdir(parents=True, exist_ok=True)
    key_path = pki_dir / "secret.key"
    if key_path.exists():
        return key_path.read_bytes()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass  # best-effort on platforms without POSIX permission bits (e.g. Windows)
    return key


def encrypt(key: bytes, plaintext: str) -> str:
    return Fernet(key).encrypt(plaintext.encode()).decode()


def decrypt(key: bytes, token: str) -> str:
    return Fernet(key).decrypt(token.encode()).decode()
