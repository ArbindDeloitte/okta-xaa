# Same agent, different scopes per user

**What you'll show:** one agent app, one Okta agent, one Okta connection (all 7 scopes allowed). Two people sign in, and each
gets a different set of scopes and tools, depending on who they are.

| Signs in | Role | Scopes the token gets | Tools the agent sees |
|---|---|---|---|
| Marcus (support) | `support` | all 7 | all 8, including `create_return` (RMA) |
| Priya (analyst) | `viewer` | `products:read` `inventory:read` `orders:read` | 4 read-only tools |

## How it works

1. Both users use the **same agent** and the same Okta connection, which allows all 7 scopes.
2. Okta's ID-JAG identifies the person (`sub`, and `email` if Okta includes it).
3. The retail authorization server looks the person up in `PORTAL_USER_ROLES` and issues a token with **only that role's scopes**.
4. The agent panel shows the reduced scopes and the role. The agent is only offered the tools those scopes allow.
5. The portal enforces the same cap again on every call (a viewer's token calling a write API directly gets `403 insufficient_scope`).

Which scopes each role gets is defined in one place: [packages/shared/roles.ts](../packages/shared/roles.ts)
(`viewer` = 3 read scopes; `support` and `manager` = all 7, and `manager` has no RMA credit limit).

> **Where this lives:** Okta's XAA connection sets scopes **per agent and per app** (allow any / allow only these / block these). I found no
> per-user or per-group scope setting in Okta's docs or API, so Okta can't give two users different scopes on the same agent by itself.
> The per-user decision is made by the auth server from the user's identity in the ID-JAG. Okta still controls who may use the agent at all
> (assignments) and the ceiling of scopes the agent can ever get.

## Setup

**1. A second user in Okta** (skip if you already have two). Directory → **People** → **Add person**; activate them / set a password.

**2. Assign both users to the same agent.** Directory → **AI Agents** → your agent → **User access** → **Application → Assignments** → add both.
Nothing else changes in Okta: keep the connection on **Allow any scope** (or all 7).

**3. Find how the portal sees each person.** Sign in to the agent as each user once and click **Run XAA exchange**
(use a private/incognito window for the second person: Okta and the agent cookie are shared across normal tabs).
Then open the portal console, http://localhost:3101 → **Users & roles**. It lists each person by `email` (or by Okta `sub` like `00u...` if
the ID-JAG has no email) with their role. New people get `PORTAL_DEFAULT_ROLE` (`support`, i.e. all scopes).

**4. Assign roles in `.env`.** Use exactly what the console showed:

```
PORTAL_USER_ROLES=marcus@yourco.com=support,priya@yourco.com=viewer
```

For a quick single-user test you can set only your own: `PORTAL_USER_ROLES=<your email or 00u... id>=viewer`.
The services restart themselves when `.env` changes (when started with `npm start`).

**5. Refresh and compare.** In each window click **Run XAA exchange** (it forces a fresh token; otherwise a cached one lives up to 10 minutes).

* Marcus: panel says `Connected as role "support"`, 7 scopes, 8 tools. *"Create an RMA for the AP25 on SO-10001"* works.
* Priya: `Connected as role "viewer"`, 3 scopes, 4 tools. The same request is refused, because the tool isn't offered to her agent.

The portal console's **Audit log** shows both users' calls under the same agent.

## Troubleshooting

* **Both users still get 7 scopes:** their identifier in `PORTAL_USER_ROLES` doesn't match. Compare it with **Users & roles** (email vs `sub`, exact spelling).
* **Role changed but the panel didn't:** click **Run XAA exchange** (cached token), or wait out the 10 minutes.
* **Step 3 `invalid_scope: This user's role "viewer" may not use any of the requested scopes`:** your `RETAIL_SCOPES` contains only scopes the role doesn't allow.
* Want separate **agents** with different Okta scopes instead? See [LIMITED_AGENT.md](LIMITED_AGENT.md).
