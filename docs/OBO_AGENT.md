# On-behalf-of (OBO) agent app

A second agent app, `packages/agent-obo`, that talks to the **same portal and the same data** as the XAA agent but gets its
portal token through Okta's OAuth 2.0 **on-behalf-of token exchange** (RFC 8693) instead of Cross App Access.
It reuses the XAA agent's chat engine, LLM settings and web page; only the way it gets a token differs.

| | Direct XAA (`packages/agent`, port 3000) | OBO (`packages/agent-obo`, port 3200) |
|---|---|---|
| User signs in at | Okta org authorization server | an Okta **custom** authorization server (the "sign-in server") |
| What the agent exchanges | refresh token → ID-JAG | the user's **access token** |
| Who issues the portal token | our retail auth server (after Okta's ID-JAG) | **Okta itself**, from a second custom server (the "exchange server") |
| Agent identity | first-class AI agent with a connection | an **API Services app** (a service app) |
| Scopes limited by | the agent's connection in Okta | the custom server's access-policy rule |
| Token names the agent | `client_id` | `cid` and `act.sub` |
| Retail auth server needed | yes | no |

Okta's own guidance favours XAA for AI agents, because a service app that exchanges user tokens is easier to over-grant.
This app exists so you can show the two side by side.

```
browser ──sign in──▶ OBO app ──code+PKCE──▶ SIGN-IN server (custom AS #1)   → the user's own access token
                       │
                       ├─ RFC 8693 token exchange (service app, Basic auth) ──▶ EXCHANGE server (custom AS #2, trusts #1)
                       │                                                         → portal token: sub = user, act = agent
                       └─ MCP call with that token ──▶ HPE Order Portal (trusts only server #2; applies the user's role)
```

Two servers keep the roles apart: the sign-in server only ever hands out tokens that mean "this person is signed in", and the
portal refuses them. Only the exchange server can mint a token the portal accepts, and only for the service app.
(One server also works: leave `OBO_LOGIN_ISSUER` empty and `OBO_ISSUER` does both.)

## Okta setup (once)

Security → API → Authorization Servers.

1. **Sign-in server** (custom AS #1, e.g. `default` or a new one called "HPE users").
   * Note its **Issuer URL** → `OBO_LOGIN_ISSUER`.
   * It needs no custom scopes. Add an **access policy** assigned to the login app (step 3) with a rule that allows the
     **Authorization Code** grant.
2. **Exchange server** (custom AS #2, a new one called "HPE order portal").
   * **Issuer URL** → `OBO_ISSUER`. **Audience** (for example `api://hpe-order-portal`) → `OBO_AUDIENCE`.
   * **Scopes:** add the seven portal scopes: `products:read`, `inventory:read`, `orders:read`, `customers:read`,
     `orders:write`, `returns:read`, `returns:write`.
   * **Settings → Trusted servers → Add:** pick the sign-in server (#1). This is what lets #2 accept #1's tokens as the subject.
   * **Access policy** assigned to **the service app** (step 4) with a rule that allows the **Token Exchange** grant and the
     scopes you want available. They are the most any user can get through this agent.
3. **Login app** (Applications → Create App Integration → OIDC → **Native**, or Web).
   * Grant types: Authorization Code (add Refresh Token if you set `OBO_OFFLINE_ACCESS=true`).
   * Sign-in redirect URI: `http://localhost:3200/callback`.
   * Assign the users who may sign in. Client ID → `OBO_LOGIN_CLIENT_ID` (a Web app also needs its secret in `OBO_LOGIN_CLIENT_SECRET`).
4. **Service app** (Applications → Create App Integration → **API Services**).
   * Under General Settings → Advanced, enable the grant type **Token Exchange**.
   * Client ID and secret → `OBO_SERVICE_CLIENT_ID`, `OBO_SERVICE_CLIENT_SECRET`.

## `.env`

Fill the `OBO_*` block from `.env.example` (both issuers, the audience, the two client IDs, the service secret). Restart the portal
too: it reads `OBO_ISSUER` and `OBO_AUDIENCE` and from then accepts the exchange server's tokens as well as the retail auth
server's. It does not trust the sign-in server.

## Run

```
npm run start:obo     # OBO agent + portal      (the retail auth server is not needed)
npm run start:all     # XAA agent + OBO agent + auth server + portal
```

Open `http://localhost:3200`, sign in, click **Run OBO exchange**. The trace shows the three steps: the user's token, the
exchange (with the `act` claim naming the service app), and the portal's verdict (role, effective scopes, acting agent).

## How roles and scopes apply

* **Okta's policy** decides which scopes the exchanged token may carry. If the rule allows only some of the requested ones and
  Okta answers `invalid_scope` naming the refused scopes, the app retries with the rest and the trace says so. If Okta denies the
  whole request (`access_denied`, "Policy evaluation failed"), the error is shown with a hint; narrow `OBO_SCOPES` to what the
  rule allows.
* **The user's role** still applies in the portal: Okta does not know our roles, so the portal reads `PORTAL_USER_ROLES` (by
  the user's `00u…` id or email) and caps the token's scopes. Viewers see only the read tools. One entry covers every path.
* **Audit.** The portal's audit log records the user, the role, the calling app (`cid`) and the **actor** (`act.sub`).

## Things to know

* The portal never trusts an unverified token: signature (Okta's keys at `<issuer>/v1/keys`), issuer, audience and expiry are
  checked, and the tokens of other issuers are refused.
* The exchanged token's audience is the exchange server's audience, so `OBO_AUDIENCE` must be what you configured there.
* The exchange request goes to the **exchange** server's `/v1/token`, with the user's token from the sign-in server as the
  subject. If Okta rejects the subject token, check **Trusted servers** first; the error message says so.
* The service app has no refresh token. The user's own access token (default lifetime 1 hour) is what expires: the app then
  asks for a new sign-in, or renews it silently when `OBO_OFFLINE_ACCESS=true`.
* Okta's pages leave a few details open (token signing `typ`, whether other subject token types work). This app sends only what
  the guide shows: `grant_type`, `subject_token`, `subject_token_type`, `scope`, `audience`, with HTTP Basic client auth.
* `npm run test:obo` tests all of this against a mock Okta with two custom servers (37 checks); it has not been run against a real org.
