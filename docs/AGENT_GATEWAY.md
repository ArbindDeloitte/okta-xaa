# Okta Agent Gateway mode

The agent can reach the HPE Order Portal two ways. Pick one with the switch at the top of the right-hand panel
(it appears once `GATEWAY_MCP_URL` is set).

| | Direct XAA | Okta Agent Gateway |
|---|---|---|
| Who gets the portal token | the agent: Okta ID-JAG, then our auth server | Okta's gateway, after a one-time consent per user |
| User prompt | none | one "Connect your account" click on first use |
| Agent talks to | `https://<portal>/mcp` | `https://<org>.gateway.oktapreview.com/mcp/servers/<gateway>` |
| Tools the agent sees | all the user's role allows | the same, plus whatever you switch off in the gateway (**Manage tools**) |
| Audit | portal console | portal console **and** the gateway's *Recent activity* tab |

Both end at the same portal. Our auth server still caps scopes by the user's role (`PORTAL_USER_ROLES`) and the portal enforces
them again on every call.

## One-time setup (already done for the demo org)

1. **MCP server in Okta** (Applications and Resources → MCP Servers): resource identifier is the MCP endpoint itself,
   `https://<portal-host>/mcp`. External authorization server = `https://<auth-host>` with **both** access methods configured:
   * *Cross App Access*: issuer only (used by Direct XAA).
   * *Brokered consent*: authorize `https://<auth-host>/authorize`, token `https://<auth-host>/oauth/token`, static client
     `okta-gateway-test` with the secret in `RETAIL_GATEWAY_CLIENT_SECRET`, all scopes (used by the gateway). The gateway only
     lists servers that have brokered consent configured.
2. **`.env`**: `RETAIL_RESOURCE` = the resource identifier above; `RETAIL_AUTH_ISSUER` = `https://<auth-host>`;
   `RETAIL_GATEWAY_CLIENT_SECRET` = the same secret as in Okta; `RETAIL_GATEWAY_REDIRECT_URIS` = the callback Okta shows in the
   `/authorize` request; `GATEWAY_MCP_URL` = the gateway URL.
3. **Gateway** (Security → Agent Gateway): add the agent, add the portal MCP server as a resource connection, **Discover tools**
   (approve with your email), then **Manage tools** and select the tools to expose.
4. **Agent connection** (Directory → AI Agents → agent → Resource connections) for Direct XAA, pointing at the same MCP server.

## What the user sees in gateway mode

1. Switch to **Okta Agent Gateway**, click **Connect to gateway** (Okta sign-in at the gateway's authorization server).
2. Ask a question. First time only, the gateway answers "connection required": the chat shows a **Connect your account** button.
   It opens our HPE sign-in page; approve, then ask again.
3. Tools appear without the gateway's name prefix (`HPEOrderPortalMCPv2_` is stripped for display).

## Things to know

* **Who is the user at consent?** Two modes, `RETAIL_LOGIN_MODE` in `.env`:
  * `picker` (default): a demo page where the person chooses an identity. Not real authentication.
  * `okta`: our `/authorize` sends the person to Okta (OIDC code + PKCE) and reads the verified `sub`/`email` from the ID token,
    then shows an Approve/Deny screen with their role. It uses the agent's own Okta app and private key by default; before
    switching, add `<RETAIL_AUTH_ISSUER>/authorize/callback` to that app's **Sign-in redirect URIs** in Okta. The user id is the same
    `00u…` the XAA path sees, so one `PORTAL_USER_ROLES` entry covers both paths. `npm run test:gateway-okta` tests it with a mock Okta.
  Caveat: Okta does not tell us which user the gateway is acting for, so in principle the person who signs in here could differ
  from the gateway's user (in practice it is the same browser session).
* **State survives restarts.** The auth server keeps its signing key and refresh tokens (hashed) in `.keys/retail-auth-*.json`.
  The gateway stores tokens for a long time, so deleting these files forces every user to consent again.
* **Single source of truth for scopes.** The gateway does not know our roles; the role cap happens at our auth server on every
  token, so a role change takes effect at the next refresh.
* **Test pages.** `/gateway.html` is a minimal check (sign in, list tools, call `list_orders`). `npm run test:gateway` tests our
  `/authorize` and token endpoints, including restarts, without Okta.
