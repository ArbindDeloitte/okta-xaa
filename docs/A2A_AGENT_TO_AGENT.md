# Agent-to-agent (A2A): implementation & setup guide

Two ways for an agent in this project to call **another agent** instead of a portal or tool server: direct
(`packages/agent` speaks the real A2A wire protocol to a new agent, secured by the same Okta XAA mechanism already in
`xaa.ts`) and via the Okta MCP Bridge (`packages/agent-bridge` would let the Bridge broker the call, the same way it
already brokers MCP). Both needed one new, independent agent to call — this plan designed, and this project built,
that agent (**HPE HR Agent**, `packages/agent-hr`) and both call paths into it.

## Status

| Path | Status |
|---|---|
| **Direct** — `packages/agent` → `packages/agent-hr` | ✅ **Built and confirmed working.** Tested hermetically and live (`scripts/e2e-a2a.ts`, also run with `E2E_LIVE_LLM=1`) and confirmed against real Okta: employee lookups, scope-gated PTO writes (granting only `hr:read` correctly blocks `update_pto_request`), and a live chat demo all work end to end. |
| **Via the Okta MCP Bridge** — `packages/agent-bridge` → Bridge → `packages/agent-hr` | ⛔ **Confirmed blocked, upstream of this project.** Every Okta-side step succeeds: the custom authorization server, scopes, access policy, the native "Connect to another AI Agent" delegation, and the Bridge's own Resource + Managed Connection all configure cleanly. But the Bridge's own adapter refuses to route calls through it — its console says so verbatim: **"Connection type `IDENTITY_ASSERTION_A2A_SERVER` is not currently supported by this adapter. Routing through this connection is disabled."** No `agent-bridge` code was written for this path: there is currently nothing for it to call through. Full finding in [§6](#6-path-2--via-the-okta-mcp-bridge-confirmed-blocked). |

## Summary

- **`packages/agent-hr`** (port 3400): a small LLM-backed agent over a toy in-memory HR dataset, reachable over the
  real A2A protocol (`@a2a-js/sdk`), not MCP. It never talks to Okta itself — it only verifies bearer tokens.
- **Direct path**: `packages/agent/src/a2a.ts`, structured like `xaa.ts`, does the same two-step Okta exchange (org AS
  token-exchange → ID-JAG → target's custom AS jwt-bearer), then calls `message/send` on the HR Agent with the
  resulting token. Surfaced to the model as one local tool, `ask_hr_agent`, alongside the existing MCP tools — the
  chat loop's shape is unchanged. The UI visibly distinguishes A2A tool calls from MCP ones (a colored badge/border on
  each call in the trace log) so a viewer can tell the two governance stories apart at a glance.
- **Bridge path**: fully specified and partially wired on the Okta/Bridge side (see status table above), but not
  implemented in code, because the Bridge's adapter cannot currently route the connection type this requires.
- **One new Okta object**: **HPE HR Agent**, registered as a second AI Agent with its own Okta-native custom
  authorization server. No new registration for the direct-path caller — the existing Retail Ops Agent identity is
  reused, with one new resource connection pointed at the HR Agent.

## Contents

1. [What A2A is, and how it differs from MCP](#1-what-a2a-is-and-how-it-differs-from-mcp)
2. [How Okta secures agent-to-agent calls](#2-how-okta-secures-agent-to-agent-calls)
3. [Architecture: one new agent, two call paths](#3-architecture-one-new-agent-two-call-paths)
4. [The new component: HPE HR Agent](#4-the-new-component-hpe-hr-agent-packagesagent-hr)
5. [Path 1 — direct A2A in `packages/agent` (built, working)](#5-path-1--direct-a2a-in-packagesagent-built-working)
6. [Path 2 — via the Okta MCP Bridge (confirmed blocked)](#6-path-2--via-the-okta-mcp-bridge-confirmed-blocked)
7. [Okta console setup (as actually done)](#7-okta-console-setup-as-actually-done)
8. [Build order / what shipped](#8-build-order--what-shipped)
9. [Security & governance notes](#9-security--governance-notes)
10. [Testing](#10-testing)
11. [Open items](#11-open-items)
12. [Sources](#12-sources)

## 1. What A2A is, and how it differs from MCP

MCP connects an agent to **tools and data**: a fixed, structured, schema-typed function list that the server defines
and the client calls deterministically. Everything else already in this repo (the Retail Portal MCP server, the
Bridge's virtual MCP endpoint) is this shape. **A2A (Agent2Agent protocol)** connects an agent to **another agent**:
the message you send is a free-text task, not a function call, and the thing answering can reason, decide it needs
more information, run its own tools internally, or take a while — the protocol has task states for that (`submitted`,
`working`, `input-required`, `completed`, `failed`, …). The two are complementary, not competing: an A2A agent is free
to be an MCP client internally (ours is not, by design — see §4).

Mechanics:

- Every A2A server publishes an **Agent Card**, a JSON document at `/.well-known/agent-card.json`, describing its
  name, description, where to reach it (`supportedInterfaces[].url` in the installed SDK version, not a top-level
  `url`), and the "skills" it exposes.
- The primary operation is the JSON-RPC 2.0 method **`message/send`**: POST a `Message` (a role plus one or more
  `parts`, typically a text part) and get back either an immediate `Message` reply or a `Task` object. This project
  uses `message/send` only — single request, single reply — which fits the existing synchronous tool-call loop in
  `agent.ts` with no restructuring.
- **SDK used: `@a2a-js/sdk` v1.3.0.** Server side: `DefaultRequestHandler`, `InMemoryTaskStore`, an `AgentExecutor`
  you implement, mounted behind Express via `agentCardHandler`/`jsonRpcHandler` (`@a2a-js/sdk/server/express`). Client
  side: `ClientFactory`, `JsonRpcTransportFactory`, `DefaultAgentCardResolver`, `createAuthenticatingFetchWithRetry`.
  Auth hook: a `UserBuilder` — `(req) => Promise<User>` — is where this project's own bearer-token verification
  plugs in (`packages/agent-hr/src/auth.ts`).

## 2. How Okta secures agent-to-agent calls

Okta's agent-to-agent delegation is a documented, named feature. Console name: **"Connect to another AI Agent"**,
connection type **"Cross App Access (Agent-to-agent)"** (internal identifier `IDENTITY_ASSERTION_A2A_SERVER` — this
exact string is also what the Bridge's own console shows when it cannot route a connection of this type; see §6).

The mechanics are the same two-step exchange `xaa.ts` already implements for ordinary XAA, just retargeted — **with
two corrections versus the original plan, both confirmed live against real Okta and real errors:**

**Step 1 — token exchange at Okta's org authorization server** (RFC 8693):

| Parameter | Value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` — **confirmed required for this flow.** Ordinary XAA's `performXaa` defaults to `refresh_token` and that works fine there; this agent-to-agent flow rejected a refresh token and needed the ID token specifically. |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:id-jag` — the same ID-JAG type, no distinct agent-to-agent token type |
| `audience` | the **target agent's own custom authorization server issuer URL** (e.g. `https://{yourOktaDomain}/oauth2/{authServerId}`) |
| `resource` | **the SAME value as `audience`** — the target's own custom AS issuer URL, **not** the target agent's plain base/resource URL. This is the corrected shape: the original plan assumed `resource` should be the agent's own resource URL (e.g. `http://localhost:3400`), mirroring ordinary XAA's `cfg.retail.resource`. Sending that produced `invalid_target: Token Exchange requests must include a valid audience of the authorization server`. Setting `resource` equal to `audience` (both the issuer URL) is what Okta's System Log confirmed as the working shape. |
| client auth | `client_assertion_type`/`client_assertion`, private_key_jwt, signed with the key created at AI-agent registration |

Response: an ID-JAG, 5 minutes, single-use — identical shape to the one `retail-auth` already validates.

**Step 2 — JWT Bearer grant at the target's own custom authorization server** (RFC 7523, unchanged grant type):

`grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion` = the ID-JAG, POSTed to
`https://{yourOktaDomain}/oauth2/{authServerId}/v1/token` — an **Okta-hosted custom AS object** (an `aus…` id), not a
hand-built server like `retail-auth`.

**Confirmed gotcha — Access Policy client assignment.** The target AS's Access Policy has its own "Assigned to
clients" scoping, separate from the delegation link itself. A delegation can succeed at the org-AS step (you get a
valid ID-JAG) and still fail here with `no_matching_policy` → `access_denied` if the calling client isn't on the
policy's allowed-clients list. This bit twice during this build: once for the direct path's caller, once more
expected (not yet re-confirmed, since the Bridge path never got far enough to need it) for the Bridge's own AI Agent
identity. **Every new caller needs to be added to this list explicitly — it is not automatic, even once the
delegation itself shows as connected.** Diagnosable via Okta's System Log / Event Log: look for `LegacyEventType
app.oauth2.as.token.grant_failure`, and DebugData fields like `AuthorizationServerAudience` and `ResourceType`
(`A2A_RESOURCE_URL` / `STATIC_AS_AUDIENCE`).

**Access token audience.** The minted access token's `aud` claim, observed live, did not unambiguously confirm
whether Okta carries the `resource` parameter through to the final token or instead stamps the custom AS's own
statically-configured "Default Audience" setting — both are plausible readings of the evidence gathered during this
build, and it did not need resolving: `packages/agent-hr/src/auth.ts` accepts **either** value
(`cfg.resource` — i.e. `HR_AGENT_URL` / the AS's Default Audience — **or** `cfg.authIssuer` — the AS's own issuer URL)
as a valid `aud`. If you rebuild this against a fresh Okta tenant and hit an audience mismatch, check which of the two
the real token carries and adjust from there; both are already accepted so a fresh install should not require any
code change.

**Setup, confirmed:**

- Both sides must be **registered AI Agents** in the Okta directory — the resource picker in "Connect to another AI
  Agent" only lists AI agents, not plain Applications.
- The target's custom AS must define the custom scopes being requested (`hr:read`, `hr:write`), and its Access Policy
  must allow the JWT Bearer grant type **and** list the calling client (see the gotcha above).
- Okta's own wizard ("Connect to another AI Agent") configures both the caller and the resource side in one step —
  picking a caller, a resource (AI agent), the resource's authorization server, and its audience/resource URL. That
  audience/resource URL **locks in** for every future delegation to that same resource, so get it right the first
  time (use the exact value you intend to put in `.env` as `HR_AGENT_URL`/the AS's Default Audience, not a
  placeholder).
- Each registered AI agent gets its own OIDC app + key pair at registration. The HR Agent only ever **receives**
  calls in this project, so it never needed that key for anything our own code does.

A second, separate thing shares the same word "A2A": the **MCP Bridge's own `Resource` type** (the "Create resource"
dialog, Type = `A2A`). That is the Bridge product's own resource catalog entry, used for its *own* proxying model
(§6) — a different configuration surface from the Okta-native delegation above, even though both ultimately relate to
the same Cross App Access (Agent-to-agent) primitive. Both are needed together for the Bridge path to work in
principle: the Okta-native delegation governs authorization (who can get a token for what scopes), the Bridge's own
Resource + Managed Connection governs HTTP routing (where the Bridge actually sends the call). As §6 found, the
routing half is the one that is not implemented yet. One small UI note: the "Create resource" dialog's "MCP Protocol
Version" field is a leftover from a form shared with MCP resources — it does not apply when Type is A2A; leave it
blank.

## 3. Architecture: one new agent, two call paths

```
                                    ┌─────────────────────────────────────────────┐
                                    │   HPE HR Agent  (packages/agent-hr, :3400)   │
                                    │   @a2a-js/sdk server + its own small LLM     │
                                    │   loop over a toy in-memory HR dataset       │
                                    │   verifies Bearer tokens; never calls Okta   │
                                    └───────────────▲───────────────▲─────────────┘
                                                     │               │
                   DIRECT A2A  ✅ working            │               │   VIA BRIDGE  ⛔ blocked by the Bridge's adapter
  Retail Ops Agent (packages/agent, :3000)            │               │  HPE Ops Agent (Bridge) (packages/agent-bridge, :3300)
  ├─ reuses this user's ID token                       │              ├─ would reuse its existing Bridge OAuth session token
  ├─ Okta org AS: token-exchange → ID-JAG               │             ├─ Okta MCP Bridge: Resource "HPE HR Agent" (type A2A)
  ├─ HR Agent's custom AS: jwt-bearer → HR access token  │               + Managed Connection — both configured successfully
  └─ message/send (A2A), Bearer HR access token ─────────┘            └─ but the Bridge adapter refuses to route this
                                                                          connection type — nothing calls through it
```

Both callers expose (or would expose) the same thing to the model: a local tool `ask_hr_agent(task: string)`. The
model decides when a question needs the HR Agent and calls it like any other tool; only the plumbing underneath
differs by app. Only the direct path's tool is actually wired up and callable today.

## 4. The new component: HPE HR Agent (`packages/agent-hr`)

A deliberately small LLM-backed agent, not just a deterministic function server — that distinction is the whole point
of an A2A demo instead of one more MCP server. Port 3400 (3000 / 3200 / 3300 / 3400).

- **Data** (`src/data.ts`): 5 fictional employees (name, title, department, manager, email, PTO balance) in a mutable
  in-memory array.
- **Skills** (`src/skills.ts`): `lookup_employee` (scope `hr:read`) and `update_pto_request` (scope `hr:write`) — a
  read scope and a write scope, exactly as the retail scopes already demonstrate. Each skill's required scope is
  enforced against the verified caller's granted scopes before the skill runs, not just at the HTTP layer.
- **Its own small LLM loop** (`src/llm.ts`): receives the free-text `task` from `message/send`, runs one bounded round
  of Claude tool-use against the two skills above, then a final text turn — no open-ended agentic loop. Reuses the
  same `ANTHROPIC_BASE_URL`/Bedrock wiring style as `packages/agent/src/config.ts`, including the
  `AWS_BEARER_TOKEN_BEDROCK` → `BEDROCK_API_KEY` fallback mapping (this agent runs as its own process with its own
  config, so that mapping had to be copied here too — it was missed on the first pass and caused a confusing
  "ANTHROPIC_API_KEY (or BEDROCK_API_KEY) is not set" error even once Okta auth was passing).
- **Agent Card** (`src/card.ts`) at `/.well-known/agent-card.json`: name "HPE HR Agent", `supportedInterfaces[0].url`
  pointing at `HR_AGENT_URL`, Bearer security scheme, the two skills declared with per-skill security requirements.
- **Token verification** (`src/auth.ts`): `createRemoteJWKSet` + `jwtVerify` against `HR_AGENT_AUTH_ISSUER`, accepting
  either `HR_AGENT_URL` or `HR_AGENT_AUTH_ISSUER` as a valid `aud` (see §2). No session, no sign-in page, no cookies —
  it only ever receives a Bearer token per call. On a verification failure it still decodes (without verifying) and
  logs the claims plus the expected audiences, so a bad token's actual shape is visible without needing
  `HR_AGENT_LOG_CLAIMS` turned on.
- **Demo HR portal** (`public/index.html`, served at `/portal`): a presentable, auto-refreshing read/write view of the
  same in-memory data the agent itself reads and writes — built so a live PTO approval made through the chat agent
  shows up on this page within ~2 seconds with no manual refresh. Supports inline edit, quick +/- PTO adjustment, and
  adding new demo records, for setting up a live demo. Loopback-only unless `HR_PORTAL_PUBLIC=true` (same default
  pattern as `packages/retail-portal`'s own admin console). Note: a dev tunnel forwards through a local process that
  still looks like loopback traffic to Express, so this guard does not meaningfully block tunnel-forwarded requests —
  low risk given an unguessable tunnel URL, but worth knowing if `HR_AGENT_URL` is ever pointed at a public tunnel.

**Env vars** (see `.env.example` for the authoritative, fully commented list):

| Env var | Meaning | Default |
|---|---|---|
| `AGENT_HR_PORT` | Port this agent listens on | `3400` |
| `AGENT_HR_BASE_URL` | This process's own base URL, used in its startup log only | `http://localhost:3400` |
| `HR_AGENT_URL` | **This agent's own resource/audience URL.** Must match the custom AS's "Default Audience" setting. Every caller's `resource`/`audience` at step 1 must resolve to this agent's issuer (§2) — this var is what the Agent Card advertises as where to actually send `message/send` calls, so it must be reachable by whoever is calling (localhost is fine for the direct path; anything reaching in from outside this machine needs a public URL). | `http://localhost:3400` |
| `HR_AGENT_AUTH_ISSUER` | The Okta custom authorization server's issuer URL that mints this agent's callers' tokens | *(required — no default)* |
| `HR_AGENT_SCOPES` | Scopes this agent's skills are gated by | `hr:read hr:write` |
| `HR_AGENT_LOG_CLAIMS` | Set to `claims` to log every verified caller's decoded claims | *(off)* |
| `HR_PORTAL_PUBLIC` | Set to `true` to allow non-loopback access to `/portal` | `false` |

**npm scripts**: `npm run dev -w @xaa/agent-hr` (also `npm run dev:agent-hr`), `npm run test:a2a` for the e2e suite.

## 5. Path 1 — direct A2A in `packages/agent` (built, working)

`packages/agent/src/a2a.ts`, structured like `xaa.ts`:

- Reuses `oktaClientAuth()` from `xaa.ts` unchanged — same Okta org, same existing agent registration. No new Okta AI
  Agent was needed for this caller; only the HR Agent side is new.
- `performA2aExchange(tokens, trace)` does the two-step exchange from §2 (including the corrected `resource =
  audience` shape and the `id_token` subject type), with the same scope-narrowing retry on `invalid_scope` that
  `performXaa` already uses, and returns `{ accessToken, scope, expiresAt }`. Appends the same kind of human-readable
  `TraceStep`s the existing governance panel already renders — this shows up in the UI exactly like the XAA trace
  does.
- `callAgentOverA2a(baseUrl, task, getToken)`: caches only the Agent Card per base URL (never a `Client`), builds a
  fresh authenticated fetch + `ClientFactory` + `Client` per call, so tokens never cross-contaminate between calls or
  sessions.
- **Integration into the existing chat loop** (`packages/agent/src/agent.ts`): one new local tool, `ask_hr_agent`,
  offered to the model alongside the MCP tools whenever an `askHrAgent` callback is supplied — both the Groq and
  Anthropic tool-building code paths support it. `callTool` special-cases this name before the MCP branch. Everything
  else in `runAgent` — the tool-round loop, the trace, the UI — is unchanged.
- **Session wiring** (`packages/agent/src/index.ts`): `ensureHrAccess(req, trace)` caches the HR access token on
  `req.session.hr`, reusing the session's ID token (never the refresh token — Okta doesn't rotate it, so no renewal
  logic was needed here the way `ensureRetailAccess` needs it). A shared `withRefreshLock(sessionID, fn)` mutex
  serializes this alongside the retail exchange, since both touch the same session tokens. `POST /api/hr/connect`
  mirrors `/api/xaa/connect`; `/api/me` and every `/api/chat` response include the HR Agent's granted scope and
  expiry so the UI's governance panel can render it.
- **UI** (`public/index.html`, `app.js`, `style.css`): a new "HR Agent (A2A)" card next to the Cross App Access card,
  showing granted scopes and a manual "Run HR Agent exchange" button. In the tool-call trace log, A2A calls get a
  distinct colored left border and an `A2A` badge (vs. an `MCP` badge on ordinary tool calls) so a viewer can tell the
  two protocols apart at a glance — this was added specifically so a client audience can see the governance
  difference, not just read it.

## 6. Path 2 — via the Okta MCP Bridge (confirmed blocked)

The Bridge already proxies MCP: it resolves a URL on its **own domain** and the agent's MCP client connects to
*that*, not to the portal's real URL — the Bridge is a full terminating proxy that does the Okta exchange, then
relays to the real server. The original plan expected the same shape to hold for A2A. It does not, today:

**What was configured, and worked:**

1. **Bridge Resource**: Resources → Create resource, Type `A2A`, Name `hr-system`, URL = the HR Agent's own base URL
   (a dev tunnel was used here so the Bridge's own remote infrastructure could reach a locally-running agent, the
   same reason `retail-auth`/`retail-portal` already use tunnels rather than `localhost`).
2. **Managed Connection**: on the Bridge's own AI Agent's detail page ("Retail-Ops-Agent-Bridge") → Resource
   connections → Add resource connection → **Connect to another AI agent** → select HPE HR Agent. This single flow
   auto-filled the Authorization server and Audience/resource URL from the already-registered HPE HR Agent AS
   (confirming the audience=resource=issuer shape from §2 holds for any caller, not just the direct one), and after
   picking scopes (`hr:read`, `hr:write`) and saving, Okta confirmed **both** halves succeeded in one step:
   "Delegation ✓" and "Resource connection ✓."

**Where it stops:** the Bridge's own Connections & Resources list shows this new connection tagged `A2A Server` /
`INCLUDE_ONLY`, with the correct scopes — but with an explicit warning:

> Connection type `IDENTITY_ASSERTION_A2A_SERVER` is not currently supported by this adapter. Routing through this
> connection is disabled.

Compare this to the existing, working MCP connection shown in the same list ("HPE order portal Bridge"), which has a
real backing resource entry (`hpe-order-portal-mcp-v4`, a concrete URL, `Auth: okta-cross-app`) that the adapter
*can* route through. The HR Agent's A2A connection has no equivalent backing route — confirming this is a **Bridge
product/adapter limitation**, not a misconfiguration: Okta's core platform fully supports Agent-to-Agent delegation
(proven by the direct path), but the Bridge's HTTP-routing layer has not yet been built out to act on connections of
this type.

**Consequence for this project:** no `a2aCandidates()`/`resolveA2aUrl()` discovery code, and no `ask_hr_agent` tool,
were written in `packages/agent-bridge`. Writing speculative candidate-URL-probing code would be pointless here —
there is nothing for it to find, since routing through this connection type is explicitly disabled at the platform
level, not merely undocumented.

**If Okta ships adapter support for this connection type later:** the Okta-side configuration above should carry
over unchanged. At that point, revisit this section, build `a2aCandidates()`/`resolveA2aUrl()` next to the existing
`mcpCandidates()`/`resolveMcpUrl()` in `packages/agent-bridge/src/index.ts` (probing via a GET to
`<candidate>/.well-known/agent-card.json` rather than a live `message/send`, exactly as `tryInitialize()` already does
for MCP), reuse `callAgentOverA2a()` from `packages/agent/src/a2a.ts` for the actual call, and write
`scripts/e2e-a2a-bridge.ts` only once the Bridge's real proxy URL shape is empirically known — a mock built from
guesses would test the guess, not the integration.

**Housekeeping, not required:** since routing is disabled, there is no functional reason to keep `HR_AGENT_URL`
pointed at a dev tunnel rather than `http://localhost:3400` for ongoing direct-path use — the tunnel only mattered for
the Bridge's (currently nonfunctional) attempt to reach the agent. It's safe to leave the tunnel in place (harmless,
just an extra network hop) or revert `HR_AGENT_URL` and the custom AS's Default Audience back to `localhost` — purely
a cleanup preference, not a correctness issue either way.

## 7. Okta console setup (as actually done)

**A. Register the new AI agent** (Directory → AI Agents → Register AI Agent):

1. Name it `HPE HR Agent`. Allow users to access this agent → create a new linked OIDC app.
2. Activate it, same steps as the existing agent's setup in `OKTA_SETUP.html` (§1 there) — assign it to the same test
   user(s).

**B. Its custom authorization server (Okta-native):**

1. Security → API → Authorization Servers → Add Authorization Server. Name it (e.g. "HPE HR Agent AS"), set an
   **Audience** (this becomes `HR_AGENT_URL`, e.g. `http://localhost:3400`).
2. **Scopes**: add `hr:read` and `hr:write`.
3. **Access policy**: add a rule allowing the **JWT Bearer** grant type. **Assigned to clients: explicitly add every
   caller here** — this does not happen automatically just because a delegation link exists (§2's confirmed gotcha).
   For the direct path, this means Retail Ops Agent's client id.
4. Note its **Issuer URL** → this becomes `HR_AGENT_AUTH_ISSUER`.

**C. Wire the delegation for the direct path** ("Connect to another AI Agent"):

1. Caller = **Retail Ops Agent**. Resource (AI agent) = **HPE HR Agent**.
2. Authorization server = the one just created. Audience/resource URL = the AS's own issuer URL (the step 1 `audience`
   = `resource` value from §2 — **not** `HR_AGENT_URL` as a separate field; Okta's wizard shows a single
   audience/resource field here, pre-bound to the AS once it exists).
3. Select scopes `hr:read`, `hr:write`.
4. Confirm the caller's client id is on the Access Policy's client list (step B.3) — if the Okta System Log later
   shows `no_matching_policy` for this caller, this is the first thing to check.

**D. Bridge path — configured, confirmed blocked (see §6 for the full finding):**

1. Bridge console → Resources → Create resource: Type `A2A`, URL = the HR Agent's reachable base URL.
2. Bridge console → the Bridge's own AI Agent → Resource connections → Add resource connection → Connect to another
   AI agent → HPE HR Agent → select scopes → save. Confirms both "Delegation" and "Resource connection."
3. Same Access Policy client-list check as C.4, for the Bridge agent's own client id.
4. Result: the connection appears, correctly scoped, but tagged with the adapter's routing-disabled warning. No
   further Okta-side action resolves this — it is a Bridge product limitation, not a config gap.

**Appendix — the alternative not taken:** instead of an Okta-native custom AS, the HR Agent could run its own bespoke
Express OAuth server, exactly mirroring `packages/retail-auth` (its own signing key, its own `handleJwtBearer`, its
own `ALLOWED_SCOPES`). This is strictly more code, and buys back the "resource owner runs its own, non-Okta-hosted AS"
story the *original* XAA pattern already tells once. The Okta-native route tells a different, equally real story —
"two first-class Okta AI Agents talking to each other with nothing custom in between" — the more interesting one for
an agent-to-agent demo, and the one this project built.

## 8. Build order / what shipped

- [x] Scaffold `packages/agent-hr`: package.json, tsconfig, config, in-memory dataset, skills.
- [x] `@a2a-js/sdk` server side: Agent Card, executor, Express mount on port 3400.
- [x] Token verification middleware, tested first against a hardcoded token before wiring real Okta.
- [x] Registered HPE HR Agent in Okta + its custom authorization server.
- [x] `packages/agent/src/a2a.ts` (direct path): exchange, tool, `callTool` special-case. Verified against the real
      HR Agent.
- [x] HR portal demo UI (`public/index.html`): read, inline edit, quick PTO adjust, add-employee.
- [x] UI differentiation between MCP and A2A tool calls in the main agent's trace log.
- [x] e2e tests: `scripts/e2e-a2a.ts` (hermetic + live-LLM), zero regressions across `test:e2e`/`test:obo`/`test:bridge`.
- [ ] Bridge-side resource + Managed Connection, discovery code, and `ask_hr_agent` in `packages/agent-bridge` —
      **not built**; blocked upstream by the Bridge adapter (§6). Revisit if/when Okta ships routing support for
      `IDENTITY_ASSERTION_A2A_SERVER` connections.
- [ ] EC2 deployment (a third Caddy route + security-group rule for port 3400) — not yet done; not blocking anything
      above, same shape as the existing XAA/OBO/Bridge services when it happens.

## 9. Security & governance notes

- The ID-JAG is single-use and short-lived (5 minutes) — unchanged versus ordinary XAA; Okta enforces this itself for
  an Okta-native custom AS.
- Scopes are the only access control on the HR Agent — no per-user role layer like the portal's `PORTAL_USER_ROLES`.
  Narrowing the resource connection's scopes is what changes what the model can ask the HR Agent to do; this was
  demonstrated live (granting only `hr:read` correctly blocks `update_pto_request`).
- `hr:write` is the scope worth demonstrating being revoked live, the same way `orders:write`/`returns:write` already
  are for the portal.
- Anything the HR Agent returns is treated as untrusted input to the calling agent's own LLM turn, same as any MCP
  tool result already is in `agent.ts`.
- Token logging is opt-in and off by default (`HR_AGENT_LOG_CLAIMS`), matching the `OBO_LOG_TOKEN` pattern elsewhere
  in this project — claims only, never the raw token, and the failure path logs decoded claims too (without
  verifying) so a bad token's shape is diagnosable without turning this on.
- The HR portal's loopback guard does not meaningfully stop tunnel-forwarded traffic (§4) — low risk given an
  unguessable tunnel URL, but not a hard boundary if `HR_AGENT_URL` is ever pointed at a public tunnel for an extended
  period.

## 10. Testing

`scripts/e2e-a2a.ts`, following `scripts/e2e-obo.ts`'s shape: a mock Okta server in-process serving both the org-AS
token-exchange endpoint and the HR Agent's own AS (JWT-bearer + JWKS), the **real** `agent-hr` process spawned and
exercised over real HTTP, `packages/agent`'s own `a2a.ts`/`agent.ts` imported in-process, a mock LLM, and a mock MCP
server (needed at least one registered tool to avoid a `-32601`). Sections covered: config validation; the happy
path; scope narrowing to `hr:read` only; Okta's own scope-narrowing retry; replay/audience/resource attacks against
the HR Agent's AS; the HR Agent itself rejecting bad bearer tokens (empty, expired, wrong-audience); a full chat loop
exercising `ask_hr_agent` through a mock outer LLM; and the tool correctly absent when no `askHrAgent` callback is
supplied. Runs hermetically by default and also with `E2E_LIVE_LLM=1` against the real configured LLM provider.
`npm run test:a2a`. No Bridge-path e2e test exists or is planned, per §6.

## 11. Open items

- **Exact `act` claim nesting** on the HR access token — confirmed fields exist (`iss`, `sub`, `aud`, `scope`, `act`
  with `sub_profile`), exact nesting order was not specifically re-verified during this build beyond what already
  worked. Decode a real token if this ever matters for a feature that reads it.
- **Whether a future Bridge release adds `IDENTITY_ASSERTION_A2A_SERVER` routing support** — the Okta-side
  configuration in §7.D is already in place and should not need redoing if so; see §6 for what to build at that
  point.

## 12. Sources

- Okta, agent-to-agent token exchange guide:
  `https://developer.okta.com/docs/guides/ai-agent-token-exchange/agent-to-agent/main/`
- Okta help, Agent-to-agent connections: `https://help.okta.com/oie/en-us/Content/topics/ai-agents/ai-agent-agent-to-agent.htm`
- Okta Cross App Access concepts: `https://developer.okta.com/docs/concepts/xaa`
- `@a2a-js/sdk` on npm: `https://www.npmjs.com/package/@a2a-js/sdk`
- The Okta MCP Bridge's own admin console (Connections & Resources tab) — primary source for §6's finding; the exact
  "not currently supported by this adapter" text is quoted directly from that UI, observed live on this tenant.
- This project's own `packages/agent/src/xaa.ts`, `a2a.ts`, `agent.ts`, `index.ts`; `packages/agent-hr/src/*`;
  `packages/retail-auth/src/index.ts`; `packages/agent-bridge/src/index.ts`; `scripts/e2e-a2a.ts`,
  `scripts/e2e-obo.ts`; and `docs/OKTA_SETUP.html` / `docs/OBO_AGENT.md` / `docs/AGENT_GATEWAY.md`.
