"""Agent tokens, operator auth and command signing.

Agent tokens are derived from a master secret, so one compromised endpoint cannot
impersonate another. Commands are signed with Ed25519, so agents hold only a public
key and a compromised endpoint cannot forge orders for the rest of the fleet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets as pysecrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def new_secret(nbytes: int = 32) -> str:
    return pysecrets.token_urlsafe(nbytes)


def derive_agent_token(master_secret: str, agent_id: str) -> str:
    mac = hmac.new(master_secret.encode(), f"agent-token:{agent_id}".encode(), hashlib.sha256).digest()
    return f"{agent_id}.{b64e(mac)}"


def verify_agent_token(master_secret: str, token: str) -> str | None:
    """Return the agent ID the token proves, or None. IDs may contain anything but a final dot."""
    agent_id, sep, _ = token.rpartition(".")
    if not sep or not agent_id:
        return None
    expected = derive_agent_token(master_secret, agent_id)
    return agent_id if hmac.compare_digest(expected.encode(), token.encode()) else None


def verify_operator_token(expected: str, supplied: str) -> bool:
    return hmac.compare_digest(expected.encode(), supplied.encode())


def generate_signing_keypair() -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b64e(private_raw), b64e(public_raw)


class CommandSigner:
    def __init__(self, signing_key_b64: str):
        self._key = Ed25519PrivateKey.from_private_bytes(b64d(signing_key_b64))

    def sign(self, command: dict[str, Any]) -> dict[str, Any]:
        return {"command": command, "signature": b64e(self._key.sign(canonical_json(command)))}


def verify_command(public_key_b64: str, envelope: dict[str, Any]) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(b64d(public_key_b64))
        public.verify(b64d(envelope["signature"]), canonical_json(envelope["command"]))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False
