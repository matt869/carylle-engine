"""carylle-admin: provisioning and ledger utilities."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import sys
from pathlib import Path

from .security import derive_agent_token, generate_signing_keypair, new_secret


def cmd_init_env(args: argparse.Namespace) -> int:
    signing, public = generate_signing_keypair()
    master = new_secret()
    lines = [
        f"CARYLLE_AGENT_MASTER_SECRET={master}",
        f"CARYLLE_OPERATOR_TOKEN={new_secret()}",
        f"CARYLLE_LEDGER_KEY={new_secret()}",
        f"CARYLLE_COMMAND_SIGNING_KEY={signing}",
        f"CARYLLE_COMMAND_PUBLIC_KEY={public}",
    ]
    if args.lab:
        lines += [
            f"CARYLLE_VICTIM_TOKEN={derive_agent_token(master, 'lab-victim')}",
            f"CARYLLE_PURPLE_TOKEN={derive_agent_token(master, 'purple-synthetic')}",
        ]
    print("\n".join(lines))
    return 0


def cmd_agent_token(args: argparse.Namespace) -> int:
    master = os.environ.get("CARYLLE_AGENT_MASTER_SECRET")
    if not master:
        print("CARYLLE_AGENT_MASTER_SECRET is not set", file=sys.stderr)
        return 2
    print(derive_agent_token(master, args.agent_id))
    return 0


def cmd_gen_cert(args: argparse.Namespace) -> int:
    """Self-signed bootstrap certificate. Agents should pin it through verify_tls: <path>."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.host)])
    sans: list[x509.GeneralName] = []
    for host in [args.host, "localhost", "127.0.0.1"]:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            sans.append(x509.DNSName(host))
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(list(dict.fromkeys(sans))), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, algorithm=None)  # Ed25519 has its digest built in
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = out / "key.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    key_path.chmod(0o600)
    print(f"Wrote {out / 'cert.pem'} and {key_path}")
    return 0


def cmd_verify_ledger(args: argparse.Namespace) -> int:
    from .config import load_settings
    from .pipeline.response.action_ledger import ActionLedger
    from .store import Store

    settings = load_settings(args.config)
    key = os.environ.get("CARYLLE_LEDGER_KEY")
    if not key:
        print("CARYLLE_LEDGER_KEY is not set", file=sys.stderr)
        return 2
    store = Store(settings.server.db_path)
    result = ActionLedger(store, key, settings.server.ledger_anchor_path).verify()
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="carylle-admin", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init_env = sub.add_parser("init-env", help="Generate all server secrets as .env lines")
    init_env.add_argument("--lab", action="store_true", help="Also issue lab agent tokens")
    init_env.set_defaults(func=cmd_init_env)

    token = sub.add_parser("agent-token", help="Issue a token for an agent ID")
    token.add_argument("agent_id")
    token.set_defaults(func=cmd_agent_token)

    cert = sub.add_parser("gen-cert", help="Generate a self-signed bootstrap TLS certificate")
    cert.add_argument("--host", required=True)
    cert.add_argument("--out", default="deploy/tls")
    cert.add_argument("--days", type=int, default=365)
    cert.set_defaults(func=cmd_gen_cert)

    verify = sub.add_parser("verify-ledger", help="Verify the action ledger's hash chain")
    verify.add_argument("--config", default=None)
    verify.set_defaults(func=cmd_verify_ledger)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
