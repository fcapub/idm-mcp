---
name: agent-identity-local
description: Create or load a self-sovereign decentralized identity (DID) for an AI agent, fully offline with no server. Use when the user wants to give an agent an identity, create or set up a DID, or get a decentralized identifier without depending on an external identity service. Self-contained and portable.
allowed-tools: Bash(uv run *) Bash(python *) Bash(python3 *) Read
---

# Get agent identity (DID) — standalone

Creates or loads an AI agent's decentralized identity (DID) entirely locally,
with NO dependency on the idm-mcp server or any network service. The agent
generates its own Ed25519 keypair and mints its own DID document
(self-sovereign identity), stored in a local wallet file.

This skill is self-contained and portable: it bundles
`scripts/agent_identity.py`, whose only dependency is the `cryptography`
package.

Wallet shape: { "publicKey", "secretKey", "did", "didDocument" }
The secret key stays in the wallet on this machine and is never transmitted.

## Step 1 — Run the bundled identity script
Run `scripts/agent_identity.py` from THIS skill's directory (use its path
relative to this SKILL.md). It is idempotent: it reuses an existing keypair and
DID if the wallet already has them, otherwise it generates a keypair, builds the
DID document, and saves the wallet.

Pick whichever runner is available:

- **With uv (easiest — installs `cryptography` automatically, nothing to set up):**

      uv run --script scripts/agent_identity.py

- **With plain Python (if uv is not available):** requires `cryptography`
  (`pip install cryptography`), then:

      python scripts/agent_identity.py

Both accept the same optional arguments:
- `--entity-type` (default "AIagent"), `--description`, `--protocol`,
  `--transparency` — recorded in the DID document.
- `--wallet PATH` — wallet file location (default `agent_wallet.json`).

Example with metadata:

      uv run --script scripts/agent_identity.py --entity-type AIagent \
          --description "AIassistant" --protocol MCP --transparency 6GPDL

## Step 2 — Report
The script prints the DID and DID document as JSON, plus whether the keypair and
DID were newly created or reused. Report the agent's DID and that status to the
user. NEVER print or reveal the secret key.
