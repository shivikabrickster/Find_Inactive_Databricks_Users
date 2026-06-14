# Find Inactive Databricks Users

A Databricks notebook that flags and (optionally) deactivates **account-level users with no activity for 90+ days, including users who have never logged in** — for a Central Accounts Management (CAM) style inactivity policy.

Inactivity is computed from `COALESCE(last_login, onboarding_date, start of audit history)` using the `system.access.audit` system table, with no synthetic data. The Account Users API does not return a creation timestamp, so the onboarding date is derived from audit provisioning events.

## How it works

| Signal | Source |
|---|---|
| **Roster** — current active users | Account Users API (SDK, auto-paginates) |
| **Last login** — most recent successful login per user | `system.access.audit` |
| **Onboarding date** — earliest provisioning event per user (baseline for never-logged-in users) | `system.access.audit` |
| **Floor** — used when neither exists | `MIN(event_time)` of audit history |

The floor means the query never assumes more inactivity than the audit history can prove.

## Files

- `find_inactive_databricks_users.py` — the notebook in Databricks source format. Import via **Workspace → Import → File**.

## Prerequisites (one-time)

1. Create a **service principal** in the account console, give it the **account admin** role, and generate an **OAuth secret** (client ID + secret).
2. Store both in a Databricks **secret scope**, run from the workspace web terminal or a local terminal (not a notebook cell):

   ```bash
   databricks secrets create-scope identity-admin
   databricks secrets put-secret identity-admin account-sp-client-id
   databricks secrets put-secret identity-admin account-sp-client-secret
   ```

   Secret scopes are workspace-level; create the scope in the workspace where the notebook runs.

## Usage

Open the notebook, fill in the **Configuration** cell, then run in order:

1. **Build the roster** — current active users.
2. **Confirm action names + audit span** — update the config to match what the discovery query shows for your account.
3. **Find inactive users (report-only)** — produces the candidate table.
4. **Validate** — floor reliance and spot-check.
5. **Disable** — gated: `DRY_RUN` and `TEST_ONE` are `True` by default; safelist plus a read-back `active=false` check on every call.

**Cells 1–4 are read-only. Cell 5 is the only step that changes anything.**

## Accuracy and safety

A valid (active) user will not be disabled, by design:

- **Activity is counted broadly** — interactive logins (SAML, OIDC browser, MFA, certificate, JWT) and token use (`tokenLogin`), so a user active by PAT or CLI still counts.
- **The floor never over-assumes inactivity** — it claims only as much inactivity as the audit history can prove.
- **The disable is gated** — report-only, then one test user confirmed in the console, then the full list, plus a safelist.

The one false-positive path is a login that is not counted: if your single sign-on logs sign-ins under an action not in the login list, those users look inactive. **Run the discovery cell and confirm your account's login and provisioning actions before trusting the candidates.** `oidcTokenAuthorization` is excluded by design — it fires on every API call and conflates service principals.

## Intranet / PrivateLink (no access to the account host)

If your environment cannot reach `accounts.cloud.databricks.com` (for example, PrivateLink-only with no internet egress), use the workspace-hosted account SCIM endpoint `{workspace-url}/api/2.0/account/scim/v2/` over front-end PrivateLink. It exposes the same account-level Users and Groups, so only the roster and disable steps change; the audit queries are unchanged. The notebook includes ready-to-use alternative cells at the end for this path.

**Auth (set up from workspace admin settings):** create a service principal under **Settings > Identity and access > Service principals**, grant it **Admin access** (workspace admin), and generate an OAuth secret on its **Secrets** tab (the Application Id is the client ID). Authenticate with OAuth client credentials at `{workspace-url}/oidc/v1/token` (OAuth is preferred over personal access tokens).

Notes:
- The path sets the scope: use the account-level path `/api/2.0/account/scim/v2/` so `PATCH active=false` applies across the account and all workspaces; the workspace-level Workspace Users API (`/api/2.0/preview/scim/v2/`) deactivates in that workspace only.
- Requires an identity-federated workspace, the default for new workspaces and most existing ones.
- On a non-critical user, validate that the deactivation behaves account-wide before automating, and confirm the roster count matches your account total.

## Notes

- `system.access.audit` is forward-only (365-day retention). A user provisioned before your history began is baselined on the floor and flags only once the span passes 90 days; until then, use audit log delivery files or the identity-provider / HR onboarding date.
- The service principal must hold the **account admin** role for the Account Users API and the disable call. For the workspace-hosted path above, a **workspace-admin** token is sufficient.
- Defaults are for AWS (`accounts.cloud.databricks.com`); for Azure use `accounts.azuredatabricks.net`.

## Disclaimer

Provided as-is, with no warranty. It deactivates account users — review the candidate list, keep a safelist, and test on a single user before running at scale. You are responsible for validating it against your own environment.
