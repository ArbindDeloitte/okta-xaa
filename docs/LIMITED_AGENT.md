# Add a second, limited agent

You already have **HPE Ops Agent** (all scopes). If you only want different scopes per signed-in USER, you do not need this: see [PER_USER_SCOPES.md](PER_USER_SCOPES.md). This optional page adds **HPE Ops Agent (Limited)**, which can only read (products, stock, orders),
so you can show two agents with different powers side by side, both governed by Okta.

How it works: the same code runs twice. The second copy reads `.env.limited` on top of `.env`, so it has its own port (3002), its own
Okta agent (client ID + key) and fewer scopes. Nothing else changes.

| | Agent | Limited agent |
|---|---|---|
| URL | http://localhost:3000 | http://localhost:3002 |
| Okta agent | HPE Ops Agent (your existing one) | HPE Ops Agent (Limited) (new) |
| Scopes Okta allows | all 7 | `products:read` `inventory:read` `orders:read` |
| Tools it sees | all 8 | `search_products`, `check_inventory`, `list_orders`, `get_order` |
| Agent id in the audit log | your existing client id | `limited-agent-at-retail` |

## Already done for you in the project

* `.env.limited` is created (port 3002, `limited-agent-at-retail`, a generated secret, read-only scopes).
* A separate key pair: `.keys/agent-limited-private.jwk.json`.
* The main `.env` now has `RETAIL_AGENT_CLIENTS=limited-agent-at-retail:<secret>` so the auth server accepts this agent.

You only need to do the Okta part and fill in **two** values.

## In Okta

1. **Directory → AI Agents → Register AI Agent.** Name: `HPE Ops Agent (Limited)`. Leave *Platform* and *External ID* empty. Next.
2. **User access and authentication:** choose **Create a new OIDC app linked to this AI agent**. Next.
3. **Register the public key.** Agent → **Client registration** → **Public/private key** → **Add public key**. Run
   `npm run show:key -- --name limited` and paste the JSON. Done → **Activate** → **Enable**.
   Okta may show its own **KID** for the key; if it differs from the one in the JSON, put it in `.env.limited` as `AGENT_KEY_ID=`.
4. **Configure the linked app** (Applications → the new app → General → Edit):
   * Grant types: **Authorization Code** and **Refresh Token**
   * **Sign-in redirect URI:** `http://localhost:3002/callback`
   * Save, then copy its **Client ID** into `.env.limited` as `AGENT_CLIENT_ID=`.
5. **Assign a user:** agent → **User access** → **Application → Assignments** → assign your test user (it can be the same person).
6. **Activate the agent:** **Actions → Activate**.
7. **Give it access to the portal.** Agent → **Resource connections** → **Add resource connection**:
   * Application instance: `Retail Portal`, **Enable**
   * **Resource indicator:** `http://localhost:3101`
   * **Client ID registered in this app:** `limited-agent-at-retail`
   * **Scopes: Allow specific scopes** → `products:read`, `inventory:read`, `orders:read`
   * Add.

## Run it

1. Stop the running `npm start` (`Ctrl+C`).
2. `npm run check:env -- --profile limited` should show the key and Okta client authentication as accepted.
3. `npm run start:both` starts the agent, the limited agent, the auth server and the portal.
4. Open **http://localhost:3000** (full) and **http://localhost:3002** (limited), sign in to each and click **Run XAA exchange**.

The limited agent's side panel should show only three scopes and four tools.

## Try it

| In the limited agent (3002) | Result |
|---|---|
| "Which orders are still processing?" | works |
| "Do we have HPE-1001 in Singapore?" | works |
| "Create an RMA for the Aruba AP25 on SO-10001" | it says it has no way to do that: the tool was never offered |
| "Who is account ACC-004?" | no access (`customers:read` not granted) |

The same RMA request in the full agent (3000) works. Open the portal console (http://localhost:3101, **Audit log**) to see the two
different agent client ids against the same user.

## If it fails

* **Okta `invalid_scope`:** `RETAIL_SCOPES` in `.env.limited` includes something the connection doesn't allow. It must be a subset.
* **`invalid_client` at sign-in or step 2:** wrong `AGENT_CLIENT_ID`, the key isn't Activated/Enabled, or a KID mismatch (`AGENT_KEY_ID`).
* **Step 3 "client_id does not match":** the connection's *client ID registered in this app* must be exactly `limited-agent-at-retail`.
* **Step 3 `invalid_client`:** `RETAIL_AGENT_CLIENT_SECRET` in `.env.limited` must equal the one after `limited-agent-at-retail:` in `RETAIL_AGENT_CLIENTS` in `.env`.
* **Port 3002 in use:** change `AGENT_PORT` and `AGENT_BASE_URL` in `.env.limited` and the redirect URI in Okta.
