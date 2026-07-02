---
name: agent-identity-idm
description: Establish or load an AI agent's decentralized identity (DID) via the idm-mcp MCP server. Use when the user wants to give an agent an identity, create or set up a DID, get a decentralized identifier, or register an agent's identity. Requires the idm-mcp server to be connected — do not use this skill if its tools are unavailable.
allowed-tools: idm-mcp:get_did Bash(uv run python keygen.py) Read Write
---

# Get agent identity (DID)

Establishes the agent's decentralized identity and stores it in a local wallet
(`agent_wallet.json`). The agent has ONE identity (its DID). The secret key never
leaves this machine and is never sent to the idm-mcp server.

Wallet shape: { "publicKey", "secretKey", "did", "didDocument" }

## Step 0 — Preflight: require the idm-mcp server
This skill depends entirely on the idm-mcp MCP server — Step 2 calls its
`get_did` tool. Before doing anything else, confirm the server is connected by
checking that the idm-mcp tools (e.g. `get_did`) are actually available to you.

- If the idm-mcp tools are NOT available, the server is not connected. STOP
  immediately — do not generate keys, call tools, or write the wallet. Tell the
  user this skill requires the idm-mcp MCP server and that they must connect or
  register it in their MCP client before retrying.
- Only if the idm-mcp tools are available, continue to Step 1.

## Step 1 — Ensure the agent has a keypair
- Read `agent_wallet.json` if it exists.
- If it already contains `publicKey` and `secretKey`, REUSE them — do not
  generate new keys.
- Otherwise generate a new Ed25519 keypair by running `uv run python keygen.py`,
  and read the printed Public Key and Secret Key (hex).

## Step 2 — Get the DID
- If the wallet already has a `did`, the agent already has an identity — report
  it and stop (do not call get_did again).
- Otherwise call `idm-mcp:get_did` with entity_type="AIagent",
  pk=<public key>, pktype="ed25519" (include description / protocol /
  transparency if the user provided them).

## Step 3 — Save the wallet
- Save publicKey, secretKey, did (the returned didDocument's `id`), and
  didDocument to `agent_wallet.json`.

## Report
- Report the agent's DID. NEVER print or reveal the secret key.
