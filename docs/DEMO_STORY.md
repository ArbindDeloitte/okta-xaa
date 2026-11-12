# The story: "Who is allowed to do what, and who decides?"

*A fictional scenario for an HPE-style order-operations team. People, accounts, SKUs, prices and stock are sample data.*

## Setting

An enterprise hardware vendor's order desk and support teams use AI agents to look up sales orders and enterprise accounts,
check stock across distribution centres, and file **RMAs** (return merchandise authorizations) through the **HPE Order Portal**.
The security team has one rule:

> *An agent may only do what the company's identity system has explicitly granted, for the people it was assigned to, and
> every call must be traceable to a person, an agent and a reason.*

Before Cross App Access (XAA), every agent was wired to the portal with its own long-lived API key. Nobody could say which
agent had which power, and removing access meant hunting through code. Now **Okta decides, centrally.**

## The cast

| Who | Role | Which agent | What Okta grants that agent |
|---|---|---|---|
| **Priya**, order-desk analyst | Looks up stock and orders for sales teams | **Order Desk Agent** | `products:read` `inventory:read` `orders:read` |
| **Marcus**, support engineer | Handles cancellations and RMAs | **Support Agent** | everything Order Desk has, plus `customers:read` `orders:write` `returns:read` `returns:write` |
| **Elena**, regional operations manager | Approves large credits | Support Agent | same agent, but her **portal role is `manager`** |
| **Sam**, contractor | Answers stock questions | Order Desk Agent | read-only, and capped again by a `viewer` role |

## Act 1: Priya asks the Order Desk Agent (agent-level control)

Priya asks: *"Do we have HPE-1001 (ProLiant DL380 Gen11) in Singapore?"* The agent calls `check_inventory`. **3 units.** Done.

She then asks: *"Start an RMA for the access point on SO-10001."* The Order Desk Agent has no RMA tool and says so plainly.
It didn't refuse out of politeness; the tool was **never offered to it**. Okta's connection for that agent doesn't include
`returns:write`, so the ID-JAG never carried it, so the portal's access token never had it.

> *Point for the room:* the limit isn't in the prompt and can't be talked around. The tool doesn't exist for that agent.

## Act 2: Marcus uses the Support Agent (what assignment buys you)

Marcus is assigned the Support Agent in Okta; Priya is not. He files an RMA for 1 Aruba AP25 access point ($189).
**Approved instantly**, because it is under the $5,000 limit for the `support` role.

Then an Alletra storage system, $24,500, arrived defective. The agent files it, and the portal answers **`pending_manager_approval`**.
The agent had the scope; the portal's business rule still queued it for a human.

> *Point for the room:* Okta says **which agent may call**. The portal still says **how far a given person may go**.

## Act 3: Elena, same agent, different person (user-level control)

Elena uses the same Support Agent for the same Alletra RMA. Her portal role is `manager`, so it is **approved immediately**.
Same agent, same Okta grant, different outcome, because the portal maps *her identity* (carried in the ID-JAG's `sub`/`email`)
to a role.

## Act 4: The contractor tries (defence in depth)

Suppose Sam is wrongly given the Support Agent. Okta's connection allows all the write scopes for that agent. But the authorization
server sees a `viewer` and issues Sam a token with **only the 3 read scopes**, so his agent is never even offered an RMA tool, and the
panel reads `Connected as role "viewer"`. If someone called the portal API directly with Sam's token, the portal still answers
**403 `insufficient_scope`** and logs it. **Two independent layers, and the stricter one wins.**

*This is the "same app, different scopes per user" demo; setup is in [PER_USER_SCOPES.md](PER_USER_SCOPES.md).*

## Act 5: The incident (central revocation)

Mid-week, the Support Agent is suspected of misbehaving. The Okta admin opens the agent's resource connection and removes
`returns:write`. Nothing is deployed and no key is rotated. On the agent's next exchange, `create_return` disappears from its tool
list.

*Honest detail:* an already-issued access token lives for its lifetime (10 minutes here). Revocation takes effect at the next exchange, not
instantly. Shorten `ACCESS_TOKEN_TTL_SECONDS` to tighten that window.

## Act 6: The audit

The CISO opens the portal console's **Audit log**: every call, **who** (user), **which agent** (client), **which scope**, **allowed or
denied, and why**, including the contractor's denied RMA and Priya's attempted RMA that never reached the portal.

## How each act maps to the product

| Act | Control | Where it is set | Status in this project |
|---|---|---|---|
| 1 | Agent can't see tools it wasn't granted | Okta: agent → Resource connections → Scopes | **Works today** (one agent); narrow the scopes and click *Run XAA exchange* |
| 2 | Only assigned users can use an agent | Okta: agent → User access → Assignments | **Works today** (run the second, limited agent: see LIMITED_AGENT.md) |
| 2 | Credit > $5,000 needs a manager | Portal business rule | **Works today** (tested) |
| 3, 4 | Per-person role decides the scopes in the user's token | `PORTAL_USER_ROLES` in `.env` (see PER_USER_SCOPES.md) | **Works today** (tested with a mock Okta). Needs two Okta test users on the same agent |
| 5 | Central revocation | Okta connection | **Works today**, effective at next exchange |
| 6 | Audit | Portal console | **Works today** |

## Showing two agents side by side

This project runs a **second, limited agent** next to the main one, with a few minutes of Okta setup and no code changes:
see [LIMITED_AGENT.md](LIMITED_AGENT.md). Use the full agent as the Support Agent (port 3000) and the limited one as the Order Desk Agent
(port 3002), and the audit log shows the two agent client ids against the same user.

Acts 3 and 4 (one person, different roles) are shown by changing the signed-in user's role in `PORTAL_USER_ROLES`.

## One-line takeaway

**Okta decides which agent can do what, and for whom. The app decides how far each person may go. Every call leaves a trail.**
