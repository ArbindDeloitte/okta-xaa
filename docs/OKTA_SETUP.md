# Okta setup: step by step

Based on Okta's *AI agent-to-app* Cross App Access (XAA) help pages:
[Configure Cross App Access](https://help.okta.com/oie/en-us/Content/Topics/Apps/apps-cross-app-access.htm),
[Configure the AI agent (requesting app)](https://help.okta.com/oie/en-us/Content/Topics/Apps/apps-config-requesting-apps.htm),
[Configure the resource app](https://help.okta.com/oie/en-us/Content/Topics/Apps/apps-config-resource-app.htm),
[Configure the XAA connection](https://help.okta.com/oie/en-us/Content/Topics/Apps/apps-config-xaa-connection.htm) and the
[OIDC requesting-app post](https://developer.okta.com/blog/2026/08/21/xaa-oidc-requesting).
Menu names come from those pages; Okta changes its console often, so if a label differs, go by the intent.

**Prerequisites:** an Okta org with the **Single Sign-On** product, an admin who can manage AI agents, and at least one test user.
(Okta limits XAA under SSO to 250 ID-JAG tokens per user, per resource app, per month.)

## Values you will exchange between Okta and `.env`

| Value | Where it comes from | Goes into |
|---|---|---|
| Okta org URL, e.g. `https://acme.oktapreview.com` | your org | `OKTA_ISSUER` |
| Agent **Client ID** | Step 1 (linked app → General → *Client Credentials*, or AI agent → Client registration) | `AGENT_CLIENT_ID` |
| Agent **public key** (the private half stays on your machine in `.keys/`) | `npm run gen:key` / `npm run show:key` | Step 1.4 in Okta; `AGENT_AUTH_METHOD=private_key_jwt` |
| Resource **Issuer URL** `http://localhost:5101` | you choose (the `retail-auth` service) | Step 2 field *Issuer URL* **and** `RETAIL_AUTH_ISSUER`, identical |
| **Resource indicator** `http://localhost:3101` | you choose (the portal) | Step 3 field *Resource indicator* **and** `RETAIL_RESOURCE`, identical |
| **Agent's client ID registered in the resource app** `agent-at-retail` | you choose | Step 3 field of that name **and** `RETAIL_AGENT_CLIENT_ID` |
| Agent's secret at the retail AS | you choose (never given to Okta) | `RETAIL_AGENT_CLIENT_SECRET` |
| Scopes | the 7 scopes below | Step 2 *Scopes*, Step 3 *Scopes*, `RETAIL_SCOPES` |

Scopes: `products:read` `inventory:read` `orders:read` `customers:read` `orders:write` `returns:read` `returns:write`

---

## Step 1: Create the AI agent (the requesting app)

1. Admin Console → **Directory → AI Agents → Register AI Agent**.
2. **Profile:** name `Retail Ops Agent`, add a description (optional) → **Next**.
   The **Identifier** section (*Platform* / *External ID*) is "recommended if available". It is for matching agents built on a listed
   agent-builder platform, so leave both blank for this custom agent.
3. **User access and authentication → Allow users to access this agent:** choose **Create a new OIDC app linked to this AI agent** → **Next**.
   (This permanently links the agent to that app. To change it later you must delete and recreate the agent.)
   The agent is created with status **STAGED**.
4. **Register the agent's public key** (do this *before* editing the app, or Okta refuses to save it with
   `'jwks' is required when 'token_endpoint_auth_method' is 'private_key_jwt'`):
   * In the project folder run `npm run gen:key` (first time) or `npm run show:key` (to re-print it). Copy the printed **public JWK**.
   * On the AI agent → **Client registration** tab → **Configure** next to **Public/private key** → **Add public key** → paste the JWK → **Done**.
   * Click **Activate**, then **Enable** in the dialog.
   * Okta may show its **own KID** for the key, different from the one in the JWK. That's fine: if the KIDs differ, set `AGENT_KEY_ID=<the KID shown in Okta>` in `.env`.
   * Copy the **Client ID** (also visible on the linked app → **General → Client Credentials**, where *Client authentication* shows
     **Public key / Private key**, which is what we want).
5. **Configure the linked OIDC app** (Applications and Resources → Applications → the linked app → **General → Edit**). If the wizard didn't ask, set:
   * Grant types: **Authorization Code** and **Refresh Token** (under *Core grants*). The refresh token is what the agent exchanges for the ID-JAG.
   * **Refresh token behavior:** either *Use persistent token* or *Rotate token after every use* works. With rotation, the agent keeps
     the new refresh token that Okta returns and runs one exchange at a time per user session. If Okta ever answers `invalid_grant`, sign in again.
   * **Sign-in redirect URI:** `http://localhost:3000/callback`
   * **Sign-out redirect URI** (optional): `http://localhost:3000/`
   * PKCE ("Require PKCE as additional verification") can stay off; the agent always sends PKCE anyway.
6. **Assign users:** AI agent → **User access** tab → **Application → Assignments** → assign your test user or group.
   (The linked app starts inactive, so it may show under the *Inactive* tab.)
7. **Activate the agent:** AI agent page → **Actions → Activate**.

Put in `.env`: `OKTA_ISSUER`, `AGENT_CLIENT_ID`, `AGENT_AUTH_METHOD=private_key_jwt`. No client secret is needed.

## Step 2: Create the Retail Portal app (the resource app) and enable XAA on it

1. **Applications and Resources → Applications → Create App Integration → OIDC - Web Application** (a *custom* OIDC app supports XAA).
   Name it `Retail Portal`. Any placeholder redirect URI is fine, e.g. `http://localhost:3101/callback`.
   **Skip group assignments for now.** Save.
2. Open `Retail Portal` → **Machine Assignments** tab → **Callers** tile → **Edit** next to **Cross App Access (XAA)** → **Enable**.
3. Fill in:
   * **Issuer URL:** `http://localhost:5101`. The base URL of the resource authorization server, which here is the `retail-auth` service.
   * **Audience/tenant ID:** optional; leave empty (only needed for multi-tenant servers).
   * **Scopes:** add the 7 scopes above, **one per field** (**+ Add** for more).
4. **Save.**

## Step 3: Connect the agent to the Retail Portal (the central policy)

1. **Directory → AI Agents →** `Retail Ops Agent` → **Resource connections** tab → **Add resource connection**.
2. **Application → Application instance:** select `Retail Portal`, then **Enable**.
3. Fill in:
   * **Resource indicator:** `http://localhost:3101`
   * **AI agent's client ID registered in this app:** `agent-at-retail`
   * **Scopes:** **Allow any scope**, or **Allow specific scopes** (to try governance, pick only `products:read orders:read`).
4. **Add.**

This is the screen the admin uses to narrow or revoke the agent later. Change the scopes or disable the connection, and the agent's tool list changes on its next exchange.

## Step 4: Configure the project

```powershell
copy .env.example .env
```

Fill in `.env`:

```
OKTA_ISSUER=https://<your-org>.oktapreview.com
AGENT_CLIENT_ID=<from Step 1>
AGENT_AUTH_METHOD=private_key_jwt               # key at .keys/agent-private.jwk.json
ANTHROPIC_API_KEY=<your key>

RETAIL_AUTH_ISSUER=http://localhost:5101        # = Step 2 Issuer URL
RETAIL_RESOURCE=http://localhost:3101           # = Step 3 Resource indicator
RETAIL_AGENT_CLIENT_ID=agent-at-retail          # = Step 3 client ID
RETAIL_AGENT_CLIENT_SECRET=<choose a secret>
```

Then:

```powershell
npm install
npm run check:env      # checks .env, the key, and that Okta accepts the agent's key
npm start
```

## Step 5: Verify

1. Open http://localhost:3000 → **Sign in with Okta** (as the assigned user).
2. Click **Run XAA exchange**. Expect three green steps:
   1. User session (refresh token + ID token)
   2. Okta: refresh token → ID-JAG
   3. Retail authorization server: ID-JAG → access token
3. Expand step 2's claims. You should see header `typ: oauth-id-jag+jwt`, `iss` = your Okta org, `aud` = `http://localhost:5101`,
   `client_id` = `agent-at-retail`, and `scope` = what the connection allowed.
4. Ask "Which orders are still processing?" Open http://localhost:3101 → **Audit log** to see the call.
5. Test central governance: in Step 3 change **Scopes** to specific ones, then click **Run XAA exchange** again. The *MCP tools visible* list shrinks.

## If something fails

| Trace shows | Check |
|---|---|
| Saving the linked app fails with `'jwks' is required when 'token_endpoint_auth_method' is 'private_key_jwt'` | The public key isn't registered yet: do Step 1.4 first, then save the app settings |
| Step 3: *returned HTTP 404 (text/html) instead of OAuth metadata*, or "Not Found" HTML | Another program owns the auth server's port (common on Windows: a Python/Flask app on 5001 can share the port with Node, and `localhost` then reaches the wrong one). Change `AUTH_PORT` and `RETAIL_AUTH_ISSUER` to a free port (this project uses 5101), update **Issuer URL** in Okta (Step 2.3) to match, and restart. The auth server now warns at startup if the port is shared |
| Step 1: *Okta did not issue a refresh token* | Step 1.5: **Refresh Token** grant enabled on the linked app; sign out and sign in again. (Or set `XAA_SUBJECT_TOKEN=id_token` to use the older ID-token exchange.) |
| Step 2 `unsupported_grant_type` / `unauthorized_client` | Agent is **Active**; the **Resource connection** exists and is **Enabled**; the user is assigned to the agent (Step 1.6) |
| Step 2 `access_denied` | Okta policy denied it: wrong user, missing assignment, or scope not allowed on the connection |
| Step 2 `invalid_target` / audience errors | **Issuer URL** (Step 2.3) ≠ `RETAIL_AUTH_ISSUER`, or **Resource indicator** ≠ `RETAIL_RESOURCE` |
| `invalid_client` (Step 2, or at sign-in) | Okta rejected the agent's signed assertion: wrong `AGENT_CLIENT_ID`; the registered public key isn't the one in `.keys/` (compare `npm run show:key`); the **KID** shown in Okta differs from the key file's kid and `AGENT_KEY_ID` isn't set; the key isn't **Activated/Enabled**; or you re-ran `gen:key --force` without re-registering. `npm run check:env` tests exactly this |
| Step 2 `invalid_scope` | A requested scope isn't defined on the resource app (Step 2.3) or isn't allowed on the connection |
| Step 2 `invalid_grant` | Refresh token expired or revoked: sign in again |
| Step 3 `client_id does not match` | **AI agent's client ID registered in this app** ≠ `RETAIL_AGENT_CLIENT_ID` |
| Step 3 `signature validation failed` | `OKTA_ISSUER` must be the same org the ID-JAG came from |
| Agent sees fewer tools than expected | Okta granted fewer scopes: governance working as intended |
| Portal says `forbidden_for_role` | Okta allowed it but the user's portal role doesn't. Set `PORTAL_USER_ROLES` (see below) |

### Using a client secret instead (fallback)

Only if your app is set to **Client secret** (linked app → General → Client Credentials → Edit → *Client secret*): generate a secret under the agent's
**Client registration**, then set `AGENT_AUTH_METHOD=client_secret` and `AGENT_CLIENT_SECRET=...` in `.env`.

### Portal roles

The portal maps the ID-JAG's `email` claim, or else its `sub` (an Okta ID like `00u...`), to a role. Find who the portal saw at
http://localhost:3101 → **Users & roles**, then set for example:

```
PORTAL_USER_ROLES=alice@example.com=manager,00u1abcdEXAMPLE=viewer
PORTAL_DEFAULT_ROLE=support
```

## Open questions (couldn't be confirmed from the docs)

* **Does Okta need to reach the Issuer URL?** The help page says Okta "uses it for token verification requests". If Step 2 fails with
  target/audience errors even though the values match, `localhost` may be unreachable from Okta. Expose `retail-auth` through an HTTPS tunnel
  (ngrok, Cloudflare Tunnel), then use the tunnel URL for both the Step 2 **Issuer URL** and `RETAIL_AUTH_ISSUER`. The auth server also answers
  `/.well-known/openid-configuration`, in case Okta looks for that.
* Which authorization server Okta uses to mint the ID-JAG isn't stated on the help pages. Okta's blog says the **org** authorization server, so `OKTA_ISSUER` is the plain org URL.
* Whether `email` appears in the ID-JAG (use `sub` in `PORTAL_USER_ROLES` if not).
* Whether the optional `resource` parameter is accepted: set `XAA_SEND_RESOURCE=false` to drop it.
