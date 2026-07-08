# IDM MCP Server

A mock **identity-management MCP server** for decentralized identity. It exposes
tools to mint DIDs, issue signed W3C-style Verifiable Credentials (VCs), and
verify them — over the [Model Context Protocol](https://modelcontextprotocol.io).

> **Status: mock / proof-of-concept.** State is held in memory (not persistent),
> the issuer signing key is regenerated on every restart, and several fields are
> simplified for demonstration. See [Limitations](#limitations).

## Features

- `get_did` — mint a `did:ietf:<uuid>` identifier + record from an agent's public key.
- `resolve_did` — look up a DID document by DID, or list all registered DIDs.
- `get_vc` — issue an Ed25519-signed Verifiable Credential for a subject DID, and store it.
- `verify_vc` — verify a credential's issuer signature and validity window.
- `resolve_vc` — look up a credential by its id, or list all issued credentials.
- `list_credentials` — list all credentials issued to a subject DID.
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
# Run the server (default transport: stdio)
uv run python main.py

# Serve over Streamable HTTP instead (http://127.0.0.1:8000/mcp)
uv run python main.py --transport streamable-http

# Develop / test interactively with the MCP Inspector (opens a browser UI)
uv run mcp dev main.py
```

The transport is chosen with `--transport {stdio,streamable-http}` (default
`stdio`) — no code edits needed.

### Using it from Claude Code

Pick one — the launch command states the transport, so there's nothing in the
code to keep in sync:

**Option A — stdio** (Claude Code launches the server for you):

```bash
claude mcp add idm-mcp -- uv --directory /path/to/idm_mcp run python main.py --transport stdio
```

**Option B — streamable-http** (you run the server yourself, then register the URL):

```bash
uv run python main.py --transport streamable-http
claude mcp add --transport http idm-mcp http://127.0.0.1:8000/mcp
```

## Generating a keypair

The tools operate on an Ed25519 keypair that the agent owns. To generate one, run:

```bash
uv run python keygen.py
# Public Key: <64 hex chars>
# Secret Key: <64 hex chars>
```

The **public key** (hex) is what you pass as `pk` to `get_did`. Keep the
**secret key** with the agent — it is never sent to the server.

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

### `resolve_did(did="")`

Looks up a DID document by DID, or lists all registered DID documents.

| Param | Required | Description |
|-------|----------|-------------|
| `did` | no | The DID to resolve. If omitted, returns a list of **all** registered DID documents. |

Returns the matching DID document (when a DID is given) or a list of all
documents (when omitted). Raises if the DID is unknown.

### `get_vc(subjectID, content, keyType, signType, usage)`

Issues and stores a Verifiable Credential for a subject DID.

| Param | Required | Description |
|-------|----------|-------------|
| `subjectID` | yes | The subject's DID (as minted by `get_did`). |
| `content` | yes | What the credential grants, e.g. `"callTools"`. |
| `keyType` | yes | Recorded as the proof's cryptosuite value, e.g. `"Ed25519"`. |
| `signType` | yes | signature scheme, e.g. "asy"; Reserved (currently unused; only asymmetric signing is performed). |
| `usage` | yes | Intended use, e.g. `"authorization"`. |

The credential is signed by the issuer key over a **canonical serialization**
(sorted-key compact JSON, with `proof` empty at signing time).

### `verify_vc(vc)`

Verifies a credential's issuer signature **and** its validity window.

| Param | Required | Description |
|-------|----------|-------------|
| `vc` | yes | The Verifiable Credential (as returned by `get_vc`) to verify. |

Rebuilds the exact signed bytes (`proof` reset to `""`), checks the Ed25519
signature, then confirms the current time is within `validFrom`/`validUntil`.
Returns `{"valid": bool, "issuer": ..., "subjectId": ..., "reason": ...}` — with a
distinct `reason` for a bad signature, an expired credential, or one not yet valid.

> Verifies **any** issuer whose DID is registered (via `get_did`) — it resolves
> the issuer's public key from its DID document (`resolve_did` + multibase decode).
> This confirms the credential is *authentic* for its claimed issuer.

### `resolve_vc(vc_id="")`

Looks up a Verifiable Credential by its id, or lists all issued credentials.

| Param | Required | Description |
|-------|----------|-------------|
| `vc_id` | no | The VC id to resolve. If omitted, returns a list of **all** issued credentials. |

Returns the matching VC (when an id is given) or a list of all VCs (when
omitted). Raises if the id is unknown.

### `list_credentials(subject)`

Lists all Verifiable Credentials issued to a subject DID.

| Param | Required | Description |
|-------|----------|-------------|
| `subject` | yes | The subject DID (`credentialSubject.id`) whose credentials to list. |

Returns a list of that subject's credentials (an **empty list** if it holds none
— a filter query, so an unknown subject is not an error).

## Example flow

An MCP client — an agent, Claude Code, or the MCP Inspector — calls the tools in
sequence. The agent supplies its own Ed25519 public key (hex) when requesting a
DID (see [Generating a keypair](#generating-a-keypair)).

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

## Agent Skills

The repo also ships **Agent Skills** (under `.claude/skills/`) — playbooks that
teach an AI agent how to obtain and use decentralized identity. A skill provides
the *workflow*; the MCP server (or a bundled script) provides the *capability*.

| Skill | What it does | Needs the server? |
|-------|--------------|-------------------|
| `agent-identity-local` | Generate a keypair and mint a DID document **locally** (self-sovereign). Bundles a self-contained script that runs with just `uv` (or `python` + `cryptography`). | No — fully standalone / portable |
| `agent-identity-idm` | Obtain a DID by calling the server's `get_did`; reuses an existing keypair or generates one, then stores the wallet. | Yes (`idm-mcp`) |
| `agent-credential` | Establish identity and apply for capability Verifiable Credentials (`get_vc`) — one DID, many VCs. | Yes (`idm-mcp`) |

Each skill manages a local **wallet** (`agent_wallet.json`) holding the agent's
keypair, DID, and credentials. The secret key stays with the agent and is never
sent to the server.

To use a server-dependent skill, register the MCP server with your client (see
[Using it from Claude Code](#using-it-from-claude-code)). `agent-identity-local`
needs nothing but `uv`.

## Project structure

```
idm_mcp/
├── main.py         # FastMCP server + the get_did / get_vc / verify_vc tools
├── keygen.py       # Ed25519 key generation + sign/verify primitives (hex-encoded keys)
├── pyproject.toml  # uv project + dependencies
├── README.md
└── .claude/
    └── skills/     # Agent Skills (agent-identity-local, agent-identity-idm, agent-credential)
```

## Limitations

This is a mock, not production identity infrastructure:

- **In-memory only** — the DID and VC registries and the issuer key live in
  process memory and are lost on restart.
- **Local registry, no external resolution** — verification works only for
  issuers whose DIDs were registered with *this* server; there is no global/
  external DID resolution.
- **`signType` is unused**, and `pktype` is not validated (only `ed25519` is
  actually handled; `pk` is validated to be a 32-byte Ed25519 key).
- **Canonical JSON signing**, not full JSON-LD Data Integrity canonicalization.
