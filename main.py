"""IDM MCP server: decentralized identity tools over MCP.

Exposes tools to mint DIDs (get_did), issue signed Verifiable Credentials
(get_vc), and verify them (verify_vc), backed by an in-process Ed25519 issuer
key and an in-memory VC store. This is a mock: state is not persistent and the
issuer key is regenerated on every restart.

Run the server (transport is selected in main(), currently streamable-http):
    uv run python main.py

Develop with the MCP Inspector:
    uv run mcp dev main.py
"""
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from mcp.server.fastmcp import FastMCP

from keygen import generate_raw_keys, sign_vc, verify_vc as verify_vc_signature

logger = logging.getLogger(__name__)

# One server instance; tools register onto it via decorators.
mcp = FastMCP("idm-mcp")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"  # multicodec varint prefix for an ed25519 public key


def _b58encode(data: bytes) -> str:
    """base58btc-encode bytes (Bitcoin alphabet)."""
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))  # leading zero bytes -> leading '1'
    return "1" * pad + out


def _b58decode(s: str) -> bytes:
    """Decode a base58btc string back to bytes."""
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def hex_to_multibase(pk_hex: str) -> str:
    """Ed25519 raw public key (hex) -> publicKeyMultibase (z6Mk...)."""
    raw = bytes.fromhex(pk_hex)
    if len(raw) != 32:
        raise ValueError(f"ed25519 public key must be 32 bytes, got {len(raw)}")
    return "z" + _b58encode(_ED25519_MULTICODEC + raw)


def multibase_to_hex(mb: str) -> str:
    """publicKeyMultibase (z6Mk...) -> Ed25519 raw public key as hex."""
    if not mb.startswith("z"):
        raise ValueError("expected base58btc multibase (z-prefixed)")
    decoded = _b58decode(mb[1:])
    if not decoded.startswith(_ED25519_MULTICODEC):
        raise ValueError("not an ed25519 multicodec key")
    raw = decoded[len(_ED25519_MULTICODEC):]
    if len(raw) != 32:
        raise ValueError(f"expected 32 key bytes, got {len(raw)}")
    return raw.hex()


@mcp.tool()
def ping() -> str:
    """Health check. Returns 'pong' so a client can confirm the server is alive."""
    return "pong"


@mcp.tool()
def echo(message: str) -> str:
    """Echo back the provided message. Useful for testing argument passing."""
    return message

@mcp.tool()
def get_did(
    entity_type: str,
    pk: str,
    pktype: str,
    description: str = "",
    protocol: str = "",
    transparency: str = "",
) -> dict:
    """
    Create a DID (Decentralized Identifier) record for an agent from its public key.

    Required:
        entity_type: the kind of agent/entity, e.g. "AI Agent" or "Toolbox".
        pk:          the agent's raw Ed25519 public key as a hex string
                     (64 hex chars, as produced by keygen.generate_raw_keys()).
                     Validated: must decode to 32 bytes, else ValueError.
                     Stored in the DID document as publicKeyMultibase.
        pktype:      the public key algorithm label, e.g. "ed25519"; recorded
                     as the verification method's type.

    Optional metadata (recorded as top-level fields on the returned record):
        description:  human-readable description, e.g. "AIassistant".
        protocol:     protocol the agent speaks, e.g. "MCP".
        transparency: transparency-log reference, e.g. "6GPDL".

    Returns the DID record dict: containing its "id" (the DID).
    """
    did_id = uuid.uuid4()
    did_id = 'did:ietf:' + str(did_id).replace('-', '')

    authentication = {
        'id': did_id+'#key-1',
        'type': pktype,
        'controller': did_id,
        'publicKeyMultibase': hex_to_multibase(pk)
    }

    vch = {
        'id': '',
        'issuer': '',
        'subjectId': '',
        'credentialHash': '',
        'signature': ''
    }

    did = {
        'id': did_id,
        'type': entity_type,
        'relatedID': '',
        'authentication': authentication,
        'description': description,
        'protocol': protocol,
        'transparency': transparency,
        'verifiableCredentialHash': vch
    }

    return did


# Issuer identity: the server mints its OWN DID by calling the get_did tool,
# treating itself as just another entity (entity_type="IDM"). This must come
# after get_did is defined. NOTE (mock): regenerates on every restart; the
# secret key stays in-process and is never returned by any tool.
_ISSUER_PK, _ISSUER_SK = generate_raw_keys()
_ISSUER_DID_DOCUMENT = get_did(entity_type="IDM", pk=_ISSUER_PK, pktype="ed25519")
_ISSUER_DID = _ISSUER_DID_DOCUMENT["id"]

# In-memory store of issued Verifiable Credentials, keyed by VC id.
# Mock: not persistent, resets on restart.
_vc_registry: dict[str, dict] = {}


@mcp.tool()
def get_vc(
    subjectID: str,
    content: str,
    keyType: str,
    signType: str,
    usage: str,
) -> dict:
    """Issue a Verifiable Credential for a subject DID and store it.

    Parameters:
        subjectID: the DID of the subject the credential is about
                   (as minted by get_did).
        content:   what the credential attests/grants, e.g. "callTools".
        keyType:   recorded as the proof's cryptosuite value, e.g. "Ed25519".
        signType:  signature scheme, e.g. "asy";
                   (reserved; only asymmetric (Ed25519) signing is performed,
                   so this value is not currently used.)
        usage:     intended use of the credential, e.g. "authorization".

    The credential is signed by the server's issuer key over a canonical
    serialization (sorted-key compact JSON with proof="").

    Returns the stored Verifiable Credential.
    """
    claim = {
        'service': content
    }

    cs = {
        'id': subjectID,
        'claim': claim
    }

    current_time = datetime.now(timezone.utc)
    valid_from = current_time.isoformat(timespec="seconds").replace("+00:00", "Z")
    valid_until = current_time + timedelta(hours=24)
    valid_until = valid_until.isoformat(timespec="seconds").replace("+00:00", "Z")

    vc_id = str(uuid.uuid4())

    vc = {
        'id': vc_id,
        'type': 'VerifiableCredential',
        'issuer': _ISSUER_DID,
        'name': 'attributeCredential',
        'description': usage,
        'validFrom': valid_from,
        'validUntil': valid_until,
        'credentialSubject': cs,
        'relatedVC': '',
        'domain': 'ietf',
        'proof': ''
    }

    # Sign a canonical serialization (sorted keys, compact) so a verifier can
    # reproduce the exact bytes. 'proof' is "" at signing time, so verification
    # must rebuild the VC with proof="" and the same json.dumps(...) call.
    payload = json.dumps(vc, sort_keys=True, separators=(",", ":"))
    signed_vc = sign_vc(_ISSUER_SK, payload).hex()

    proof = {
        'type': 'DataIntegrityProof',
        'verificationMethod': _ISSUER_DID + '#key-1',
        'cryptoSuite': keyType,
        'proofPurpose': 'assertionMethod',
        'proofValue': signed_vc
    }

    vc['proof'] = proof

    # save and return vc
    _vc_registry[vc_id] = vc
    logger.info("Issued VC %s for subject %s", vc_id, subjectID)
    return vc


@mcp.tool()
def verify_vc(vc: dict) -> dict:
    """Verify the issuer signature on a Verifiable Credential.

    Rebuilds the exact bytes that were signed (the VC with 'proof' reset to ""),
    resolves the issuer's public key, and checks the Ed25519 signature held in
    proof.proofValue.

    NOTE (mock): only credentials issued by THIS server are verifiable, because
    other issuers' DIDs are not yet resolvable (no DID registry).

    Returns {"valid": bool, "issuer": ..., "subjectId": ..., "reason": ...}.
    A credential is valid only if the signature checks out AND the current time
    is within its validFrom/validUntil window.
    """
    proof = vc.get("proof")
    if not isinstance(proof, dict) or not proof.get("proofValue"):
        return {"valid": False, "reason": "credential has no proof / proofValue"}

    # Resolve the issuer's verification key. Real resolution would fetch the
    # issuer's DID document; for now only this server's issuer key is available.
    issuer_did = proof.get("verificationMethod", "").split("#")[0]
    if issuer_did != _ISSUER_DID:
        return {"valid": False, "reason": f"cannot resolve issuer {issuer_did!r}"}
    issuer_pk = _ISSUER_PK

    result = {
        "valid": False,
        "issuer": issuer_did,
        "subjectId": vc.get("credentialSubject", {}).get("id"),
    }

    # Reconstruct the canonical payload exactly as get_vc signed it: proof = "".
    unsigned = dict(vc)
    unsigned["proof"] = ""
    payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))

    try:
        signature = bytes.fromhex(proof["proofValue"])
    except ValueError:
        return {**result, "reason": "proofValue is not valid hex"}

    # 1. Signature first — validFrom/validUntil live INSIDE the signed payload,
    #    so they can only be trusted once the signature checks out.
    if not verify_vc_signature(issuer_pk, payload, signature):
        return {**result, "reason": "signature verification failed"}

    # 2. Validity window — the credential must be currently in force.
    now = datetime.now(timezone.utc)
    try:
        if vc.get("validFrom") and now < datetime.fromisoformat(vc["validFrom"]):
            return {**result, "reason": f"not yet valid (validFrom {vc['validFrom']})"}
        if vc.get("validUntil") and now > datetime.fromisoformat(vc["validUntil"]):
            return {**result, "reason": f"expired (validUntil {vc['validUntil']})"}
    except ValueError:
        return {**result, "reason": "validFrom/validUntil is not a valid datetime"}

    return {**result, "valid": True}


def main() -> None:
    """Entry point. Runs the server."""
    logger.info("IDM MCP Server starting...")
    transport = 'streamable-http'
    if transport == 'stdio':
        mcp.run(transport="stdio")
    elif transport == 'streamable-http':
        mcp.run(transport="streamable-http")
    else:
        logger.error("Invalid transport.")


if __name__ == "__main__":
    main()
