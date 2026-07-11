---
name: agent-credential
description: Manage an AI agent's decentralized identity and capability credentials via the idm-mcp server. Use when the user wants to give an agent a DID identity, apply for a Verifiable Credential, or authorize an agent for a capability (e.g. callTools, checkEmails).
argument-hint: [capability]
allowed-tools: idm-mcp:get_did idm-mcp:get_vc idm-mcp:verify_vc Bash(uv run python keygen.py) Read Write
---

# Agent identity & credentials

The agent keeps a local wallet at `agent_wallet.json` holding its keypair, its
DID document, and every credential (VC) it has been issued. The agent has ONE
identity (its DID) and may hold MANY credentials over time. The secret key never
leaves this machine and is never sent to the idm-mcp server.

Wallet shape:
```json
{
  "publicKey": "<hex>",
  "secretKey": "<hex>",
  "did": "did:ietf:...",
  "didDocument": { "id": "did:ietf:...", "...": "the rest of the document from get_did" },
  "credentials": [ { "...": "a VC from get_vc" } ]
}
```

## Step 1 — Load or create the wallet
- Read `agent_wallet.json` if it exists, and reuse the agent's identity — its
  DID (the `did` field) — from inside it.
- If it does NOT exist, establish the agent's identity once:
  1. Run `uv run python keygen.py` and capture the printed Public Key and
     Secret Key (hex).
  2. Call `idm-mcp:get_did` with entity_type="AIagent", pk=<public key>,
     pktype="ed25519" (include description/protocol/transparency if the user
     provided them).
  3. Save publicKey, secretKey, did (the returned didDocument's `id`),
     didDocument, and an empty `credentials: []` to `agent_wallet.json`.

## Step 2 — Apply for a credential
- The capability is `$1` (e.g. "callTools", "checkEmails"); ask the user if none
  was given.
- If the wallet already holds a valid VC for this capability, stop and say so.
- Otherwise call `idm-mcp:get_vc` with subjectID=<wallet `did`>,
  content=<capability>, keyType="Ed25519", signType="asy", usage="authorization".
- Append the returned VC to `credentials` and save the wallet.

## Step 3 — Verify
- Call `idm-mcp:verify_vc` with the new credential; confirm `"valid": true`
  before treating it as authorized.

## Report
- Tell the user the agent's DID and the list of capabilities it now holds
  credentials for. NEVER print or reveal the secret key.
