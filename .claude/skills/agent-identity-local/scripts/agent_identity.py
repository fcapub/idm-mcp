# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "cryptography",
# ]
# ///
"""Self-contained agent identity tool — no idm-mcp server required.

Generates (or reuses) an Ed25519 keypair and builds a DID + DID document for an
AI agent, storing everything in a local wallet file. Fully standalone: the only
external dependency is `cryptography`, declared inline above, so it runs anywhere
with `uv run` (uv installs it in an ephemeral environment automatically).

Idempotent: if the wallet already holds a keypair and DID, they are reused.

Usage:
    uv run agent_identity.py
    uv run agent_identity.py --entity-type AIagent --description "AIassistant" \
        --protocol MCP --transparency 6GPDL --wallet agent_wallet.json
"""
import argparse
import json
import sys
import uuid
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ModuleNotFoundError:
    sys.exit(
        "This script needs the 'cryptography' package.\n"
        "  Easiest (auto-installs):  uv run --script agent_identity.py\n"
        "  Or for plain Python:      pip install cryptography"
    )

# --- base58btc + multibase (for publicKeyMultibase) -------------------------
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"  # multicodec varint prefix for an ed25519 public key


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def hex_to_multibase(pk_hex: str) -> str:
    """Ed25519 raw public key (hex) -> publicKeyMultibase (z6Mk...)."""
    raw = bytes.fromhex(pk_hex)
    if len(raw) != 32:
        raise ValueError(f"ed25519 public key must be 32 bytes, got {len(raw)}")
    return "z" + _b58encode(_ED25519_MULTICODEC + raw)


# --- key generation ---------------------------------------------------------
def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair, returned as (public_hex, secret_hex)."""
    sk = Ed25519PrivateKey.generate()
    return sk.public_key().public_bytes_raw().hex(), sk.private_bytes_raw().hex()


# --- DID document -----------------------------------------------------------
def build_did_document(pk_hex, entity_type, description="", protocol="", transparency=""):
    """Build a did:ietf DID document from a public key (mirrors idm-mcp get_did)."""
    did_id = "did:ietf:" + uuid.uuid4().hex
    authentication = {
        "id": did_id + "#key-1",
        "type": "ed25519",
        "controller": did_id,
        "publicKeyMultibase": hex_to_multibase(pk_hex),
    }
    return {
        "id": did_id,
        "type": entity_type,
        "relatedID": "",
        "authentication": authentication,
        "description": description,
        "protocol": protocol,
        "transparency": transparency,
        "verifiableCredentialHash": {
            "id": "", "issuer": "", "subjectId": "", "credentialHash": "", "signature": "",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or load a self-sovereign agent DID.")
    parser.add_argument("--wallet", default="agent_wallet.json", help="wallet file path")
    parser.add_argument("--entity-type", default="AIagent")
    parser.add_argument("--description", default="")
    parser.add_argument("--protocol", default="")
    parser.add_argument("--transparency", default="")
    args = parser.parse_args()

    wallet_path = Path(args.wallet)
    wallet = json.loads(wallet_path.read_text()) if wallet_path.exists() else {}

    # Keypair: reuse if present, else generate.
    if wallet.get("publicKey") and wallet.get("secretKey"):
        key_status = "reused existing keypair"
    else:
        wallet["publicKey"], wallet["secretKey"] = generate_keypair()
        key_status = "generated new keypair"

    # DID: reuse if present, else create locally (self-sovereign, no server).
    if wallet.get("did") and wallet.get("didDocument"):
        did_status = "reused existing DID"
    else:
        doc = build_did_document(
            wallet["publicKey"], args.entity_type,
            args.description, args.protocol, args.transparency,
        )
        wallet["did"] = doc["id"]
        wallet["didDocument"] = doc
        did_status = "created new DID"

    wallet_path.write_text(json.dumps(wallet, indent=2))

    # Report — DID + document only; never print the secret key.
    print(json.dumps({
        "keyStatus": key_status,
        "didStatus": did_status,
        "did": wallet["did"],
        "didDocument": wallet["didDocument"],
        "wallet": str(wallet_path),
    }, indent=2))


if __name__ == "__main__":
    main()
