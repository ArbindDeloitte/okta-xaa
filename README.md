# HPE Ops Agent: Okta Cross App Access (XAA) demo

An AI agent helps HPE order-desk and support staff look up sales orders and enterprise accounts, check hardware stock and file RMAs by calling an
**HPE Order Portal** over **MCP**. Access is **centrally governed by Okta** using Cross App Access
(the *Identity Assertion JWT Authorization Grant*, "ID-JAG"). There are no per-app consent screens:
the Okta admin decides which agent can reach which app, for which users, with which scopes.

Modelled on [oktadev/okta-cross-app-access-mcp](https://github.com/oktadev/okta-cross-app-access-mcp),
but with an HPE order-operations use case (sample data only), a lightweight stack (Node + TypeScript, no Docker/MySQL/Redis) and
a choice of LLM providers (Anthropic, Claude on Amazon Bedrock, or Groq).

## Architecture

```
 ┌──────────┐ 1 OIDC login (PKCE)  ┌──────────────┐
 │  Browser │ ───────────────────► │     Okta     │  enterprise IdP + XAA policy engine
 └────┬─────┘                      └───┬──────▲───┘
      │ chat                           │      │ 2 token exchange (RFC 8693):
      ▼                                │      │   ID token ──► ID-JAG   (policy checked here)
 ┌──────────────┐ ─────────────────────┘      │
 │  Agent app   │                             │
 │  :3000       │ 3 jwt-bearer grant (RFC 7523): ID-JAG ──► access token
 │ Claude + MCP │ ───────────────────────────►┌────────────────────┐
 │    client    │                             │ Retail Auth Server │ :5101  validates ID-JAG
 └──────┬───────┘ ◄─────── access token ───── └────────────────────┘        (sig, iss, aud, typ, jti,
        │ 4 MCP over HTTP + Bearer token                                     client_id, scope)
        ▼
 ┌────────────────────────────────────────────┐
 │ Order Portal  :3101  (resource server)     │  /mcp  MCP tools   · /api REST · / admin console
 │  token scopes ∩ portal role ∩ biz rules    │  audit log of every call
 └────────────────────────────────────────────┘
```

| Package | Port | Role in XAA |
|---|---|---|
| [packages/agent](packages/agent) | 3000 | **Requesting app.** Okta login, performs the 2-step XAA exchange, runs Claude with the MCP tools |
| [packages/retail-auth](packages/retail-auth) | 5101 | **Resource app's authorization server.** Trusts Okta; swaps a valid ID-JAG for a short-lived access token |
| [packages/retail-portal](packages/retail-portal) | 3101 | **Resource app.** MCP server + REST API + admin console; enforces scopes, roles, business rules; audit log |

### Where governance happens

1. **Okta (central):** the XAA connection decides whether this agent may get an ID-JAG for this user and
   which scopes it carries. The agent *only sees MCP tools* whose scope Okta granted. Revoke the connection in
   Okta and the agent loses access without touching the portal.
2. **Order Portal (local):** the user's portal role (`viewer`, `support`, `manager`) caps those scopes, and
   business rules apply (30-day return window, RMA credits over $5,000 need a manager, only `processing` orders can be cancelled).
3. **Audit:** every tool call (allowed, denied or failed) is logged with user, role, client, scope and arguments.

| Scope | Tool(s) | viewer | support | manager |
|---|---|:-:|:-:|:-:|
| `products:read` | `search_products` | ✔ | ✔ | ✔ |
| `inventory:read` | `check_inventory` | ✔ | ✔ | ✔ |
| `orders:read` | `list_orders`, `get_order` | ✔ | ✔ | ✔ |
| `customers:read` | `get_customer` | | ✔ | ✔ |
| `orders:write` | `cancel_order` | | ✔ | ✔ |
| `returns:read` | `list_returns` | | ✔ | ✔ |
| `returns:write` | `create_return` | | ✔ (≤ $5,000 auto-approved) | ✔ (no limit) |

## Quick start

Prerequisites: Node 20+, an Okta org with Single Sign-On (Cross App Access is configured under Directory → AI Agents), and an LLM key (Anthropic, Amazon Bedrock, or Groq).

1. **Configure Okta**: follow [docs/OKTA_SETUP.md](docs/OKTA_SETUP.md).
2. `npm install`
3. `copy .env.example .env` (PowerShell) and fill in the values (`OKTA_ISSUER`, `AGENT_CLIENT_ID`, `ANTHROPIC_API_KEY`). The agent authenticates to Okta with a **key pair** (`private_key_jwt`): run `npm run gen:key` once and register the printed public JWK on the agent in Okta (`npm run show:key` prints it again).
4. `npm run check:env` checks the config, your key, and that Okta accepts the agent's key.
5. `npm start` runs all three services.
6. Open **http://localhost:3000**, sign in with Okta and ask something. Open **http://localhost:3101** in a second tab for the portal console (live audit log, orders, inventory, returns, role mapping).

The right-hand panel in the agent UI shows the live flow: the decoded ID token, ID-JAG (with the scopes Okta granted) and access token, plus the MCP tools the agent can see.

### Different scopes per signed-in user (same agent)

To show one agent giving two people different scopes and tools, see [docs/PER_USER_SCOPES.md](docs/PER_USER_SCOPES.md):
the auth server issues each user a token with only their role's scopes, and the UI shows the reduced scopes. Roles are assigned per user in `.env` (`PORTAL_USER_ROLES`).

### A second, limited agent (optional)

Prefer separate agents with different powers in Okta? Run a second copy of the agent app as a separate Okta agent with read-only scopes:
[docs/LIMITED_AGENT.md](docs/LIMITED_AGENT.md) (`npm run start:both`).

### Demo script

| Ask the agent | What it shows |
|---|---|
| "Which orders are still processing?" | read tool via XAA token |
| "Do we have HPE-1001 (ProLiant DL380 Gen11) in Singapore?" | inventory tool |
| "Start an RMA for 1 Aruba AP25 access point on SO-10001, wrong model" | write tool, $189 credit auto-approved for `support` |
| "Create an RMA for the Alletra storage system on SO-10008, it arrived defective" | $24,500 is over the limit, so it goes to `pending_manager_approval` |
| "Create an RMA for the Aruba CX 6300M switch on SO-10004" | business rule: outside the 30-day window |
| In Okta, remove `returns:write` from the connection, click **Run XAA exchange** | `create_return` disappears from the agent's tools |
| Set `PORTAL_USER_ROLES=you@corp.com=viewer`, restart the portal | Okta grants the scope but the portal role denies it, and the audit log shows `forbidden_for_role` |

## Tests

`npm run test:e2e` starts the real retail-auth and retail-portal with a **mock Okta** and drives the agent's
XAA client and MCP client end to end. It covers the happy path, scope narrowing, role caps, refund limits,
audit log, ID-JAG replay, wrong audience/`typ`, bad client secret, and forged or missing bearer tokens. It does **not**
call real Okta or the Anthropic API.

## Configuration notes

* **`RETAIL_AUTH_ISSUER`** is the ID-JAG `aud`. Enter the *same* value as the resource authorization server issuer in Okta.
* **`RETAIL_AGENT_CLIENT_ID/SECRET`** are the agent's credentials *at the retail AS*. Okta puts the client id in the ID-JAG `client_id` claim, and the retail AS requires it to match.
* **`AGENT_AUTH_METHOD`** defaults to `private_key_jwt`: the agent signs a client assertion with `.keys/agent-private.jwk.json` for both sign-in and the token exchange, and the private key never leaves your machine. Use `client_secret` (plus `AGENT_CLIENT_SECRET`) only if your Okta app is set to *Client secret*.
* **`XAA_SEND_RESOURCE=false`** drops the optional `resource` parameter from the Okta token exchange if your org rejects it.
* The agent exchanges the user's **refresh token** for the ID-JAG, as in Okta's current docs (`XAA_SUBJECT_TOKEN=refresh_token`, needs the *Refresh Token* grant; `id_token` selects the older flow). If Okta rejects it with `invalid_grant`, the agent asks you to sign in again.
* **LLM provider** (`LLM_PROVIDER`, default auto): `anthropic` (Anthropic API, default model `claude-opus-5-5` via `ANTHROPIC_MODEL`; or Claude on Amazon Bedrock via `ANTHROPIC_BASE_URL` + `AGENT_MODEL_ID`) or `groq` (`GROQ_API_KEY`, default model `openai/gpt-oss-120b` via `GROQ_MODEL`; Groq has a free tier with rate limits). `npm run check:env` tests whichever is selected. `E2E_LIVE_LLM=1 npm run test:e2e` runs the agent loop against the real configured LLM.

## Troubleshooting

| Symptom (shown in the trace panel) | Likely cause |
|---|---|
| Step 2 `access_denied` / `unauthorized_client` | No XAA connection between the agent and the Retail Portal app in Okta, or the user isn't assigned to both apps |
| Step 2 `invalid_target` | Audience mismatch: `RETAIL_AUTH_ISSUER` ≠ resource AS issuer configured in Okta |
| `invalid_client` | The public key registered in Okta isn't the one in `.keys/` (compare `npm run show:key`), isn't Activated/Enabled, or `AGENT_CLIENT_ID` is wrong. `npm run check:env` tests this |
| Step 2 `unsupported_grant_type` | XAA/token exchange not enabled for the agent app |
| Step 3 `ID-JAG client_id does not match` | `RETAIL_AGENT_CLIENT_ID` differs from the client id configured on the Okta connection |
| Step 3 `invalid_scope` | Okta granted none of the scopes the agent requested |
| Step 3 `ID-JAG ... already used` | ID-JAGs are single-use (replay protection); just retry |
| Agent sees fewer tools than expected | Okta granted fewer scopes than requested, which is the governance working |

## Security notes (demo vs. production)

* Order data is in-memory sample data (fictional accounts, SKUs, prices and stock), and the retail AS signing key is generated at startup. Persist/rotate keys and use a real datastore for production.
* The portal console is unauthenticated and restricted to loopback (`PORTAL_CONSOLE_PUBLIC=true` disables the guard; don't).
* The retail AS validates: signature (Okta JWKS), `iss`, `aud`, `typ=oauth-id-jag+jwt`, expiry, `client_id`, `jti` replay (in-memory, so use a shared store if you run several instances), and intersects scopes. The portal validates the access token's signature, `iss`, `aud`, `typ=at+jwt`.
* Tool results from the portal are fed to the LLM; treat portal data as untrusted input (prompt injection) and keep write tools behind explicit user intent as the system prompt does.
* Secrets live only in `.env` and `.keys/`, which are git-ignored.