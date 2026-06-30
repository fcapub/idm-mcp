# IDM MCP Server

A mock **identity-management MCP server** for decentralized identity. It exposes
tools to mint DIDs, issue signed W3C-style Verifiable Credentials (VCs), and
verify them — over the [Model Context Protocol](https://modelcontextprotocol.io).

> **Status: mock / proof-of-concept.** State is held in memory (not persistent),
> the issuer signing key is regenerated on every restart, and several fields are
> simplified for demonstration. See [Limitations](#limitations).

## Features

- `get_did` — mint a `did:ietf:<uuid>` identifier + record from an agent's public key.
- `get_vc` — issue an Ed25519-signed Verifiable Credential for a subject DID, and store it.
- `verify_vc` — verify the issuer signature on a credential.
- `ping` / `echo` — trivial health/echo tools used to smoke-test the MCP plumbing.

The server acts as its **own credential issuer**: at startup it generates an
Ed25519 keypair and mints its own DID (by calling `get_did` with
`entity_type="IDM"`). Credentials are signed with that issuer key, which stays
in-process and is never returned by any tool.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Python 3.12 (pinned via `.python-version`)
- Node.js / `npx` — only needed for the MCP Inspector (`mcp dev`)

Dependencies (`mcp[cli]`, `cryptography`) are managed by uv and installed on first run.

## Setup

This project uses [uv](https://docs.astral.sh/uv/). Dependencies are declared in
`pyproject.toml` and pinned in `uv.lock` — together these replace a
`requirements.txt`.

After [installing uv](https://docs.astral.sh/uv/getting-started/installation/)
once, clone or unzip the project and run:

```bash
uv run python main.py
```

`uv run` automatically creates the virtual environment, installs the exact
locked dependencies, and even fetches Python 3.12 (pinned in `.python-version`)
if it's missing — no manual `venv` creation or `activate` step. Run `uv sync`
first if you'd rather install dependencies without starting the server.

**Prefer plain pip?** Export a requirements file from the lockfile, then install
the old way:

```bash
uv export --format requirements-txt --no-hashes > requirements.txt
# recipient: python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

## Running

```bash
# Run the server (transport is selected in main(); currently streamable-http,
# served at http://127.0.0.1:8000/mcp)
uv run python main.py

# Develop / test interactively with the MCP Inspector (opens a browser UI)
uv run mcp dev main.py
```

To change the transport, edit the `transport` variable in `main()` (`"stdio"` or
`"streamable-http"`).

### Using it from Claude Code

Register the server as a stdio MCP server:

```bash
claude mcp add idm-mcp -- uv --directory /path/to/idm_mcp run python main.py
```

(For stdio, set `transport = 'stdio'` in `main()`.)

## Tools

### `get_did(entity_type, pk, pktype, description="", protocol="", transparency="")`

Creates a DID record from an agent's public key.

| Param | Required | Description |
|-------|----------|-------------|
| `entity_type` | yes | Kind of entity, e.g. `"AIagent"`, `"toolbox"`. |
| `pk` | yes | Raw Ed25519 public key as hex (64 chars, from `keygen.generate_raw_keys()`). |
| `pktype` | yes | Key algorithm label, e.g. `"ed25519"`. |
| `description`, `protocol`, `transparency` | no | Optional metadata recorded on the record. |

Returns the DID record, including its `id` (the DID).

### `get_vc(subjectID, content, keyType, signType, usage)`

Issues and stores a Verifiable Credential for a subject DID.

| Param | Description |
|-------|-------------|
| `subjectID` | The subject's DID (as minted by `get_did`). |
| `content` | What the credential grants, e.g. `"callTools"`. |
| `keyType` | Recorded as the proof's cryptosuite value, e.g. `"Ed25519"`. |
| `signType` | signature scheme, e.g. "asy"; Reserved (currently unused; only asymmetric signing is performed). |
| `usage` | Intended use, e.g. `"authorization"`. |

The credential is signed by the issuer key over a **canonical serialization**
(sorted-key compact JSON, with `proof` empty at signing time).

### `verify_vc(vc)`

Verifies a credential's issuer signature. Rebuilds the exact signed bytes
(`proof` reset to `""`), resolves the issuer key, and checks the Ed25519
signature. Returns `{"valid": bool, "issuer": ..., "subjectId": ..., "reason": ...}`.

> Only credentials issued by *this* server are verifiable, because other issuers'
> DIDs are not yet resolvable (no DID registry).

## Example flow

An MCP client — an agent, Claude Code, or the MCP Inspector — calls the tools in
sequence. The agent supplies its own Ed25519 public key (hex) when requesting a DID.

1. **`get_did`** — request a DID for the agent:
   ```json
   { "entity_type": "AIagent", "pk": "4bb0…3c6f", "pktype": "ed25519",
     "description": "AIassistant", "protocol": "MCP", "transparency": "6GPDL" }
   ```
   → returns a DID record whose `id` is e.g. `did:ietf:ebc391…`.

2. **`get_vc`** — issue a credential for that DID as the subject:
   ```json
   { "subjectID": "did:ietf:ebc391…", "content": "callTools",
     "keyType": "Ed25519", "signType": "asy", "usage": "authorization" }
   ```
   → returns a signed Verifiable Credential.

3. **`verify_vc`** — pass the credential back to check its signature:
   ```json
   { "vc": { "...": "the credential returned by step 2" } }
   ```
   → `{ "valid": true, "issuer": "did:ietf:…", "subjectId": "did:ietf:ebc391…" }`

The quickest way to try this by hand is `uv run mcp dev main.py`, which opens the
MCP Inspector where you can call each tool and paste results between steps.

## Project structure

```
idm_mcp/
├── main.py        # FastMCP server + the get_did / get_vc / verify_vc tools
├── keygen.py      # Ed25519 key generation + sign/verify primitives (hex-encoded keys)
├── pyproject.toml # uv project + dependencies
└── README.md
```

## Limitations

This is a mock, not production identity infrastructure:

- **In-memory only** — issued VCs and the issuer key are lost on restart.
- **No DID registry** — DIDs aren't stored, so only this server's own credentials
  can be verified.
- **`signType` is unused**, and `pktype` is not validated (only `ed25519` is
  actually handled; `pk` is validated to be a 32-byte Ed25519 key).
- **Canonical JSON signing**, not full JSON-LD Data Integrity canonicalization.
