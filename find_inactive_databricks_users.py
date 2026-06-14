# Databricks notebook source
# MAGIC %md
# MAGIC # Disabling Inactive Databricks Users (CAM 90-day policy)
# MAGIC
# MAGIC Flags and deactivates account users with no activity for 90+ days, **including users who have never logged in**.
# MAGIC Inactivity is computed from `COALESCE(last_login, onboarding_date, start of audit history)`, with no synthetic data.
# MAGIC
# MAGIC **Cells 1-4 are read-only and safe to run. Cell 5 is the only step that changes anything, and it is gated (dry-run by default).**
# MAGIC
# MAGIC ### Prerequisites (one-time)
# MAGIC 1. Create a **service principal** in the account console (User management -> Service principals -> Add), give it the **account admin** role (Roles tab), and generate an **OAuth secret** (Credentials & secrets -> Generate secret). Copy the client ID and secret.
# MAGIC 2. Store both in a **secret scope** (Databricks CLI, from the web terminal or a local terminal, not a notebook cell):
# MAGIC    ```
# MAGIC    databricks secrets create-scope identity-admin
# MAGIC    databricks secrets put-secret identity-admin account-sp-client-id
# MAGIC    databricks secrets put-secret identity-admin account-sp-client-secret
# MAGIC    ```
# MAGIC    Scopes are workspace-level; create it in the workspace where this notebook runs.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Accuracy and safety (read first)
# MAGIC A valid (active) user will not be disabled, by design:
# MAGIC - **Activity is counted broadly** — interactive logins (SAML, OIDC browser, MFA, certificate, JWT) and token use (`tokenLogin`), so a user active by PAT or CLI still counts.
# MAGIC - **The floor never over-assumes inactivity** — it claims only as much inactivity as the audit history can prove; a never-logged-in user is flagged only with zero login and an old-enough onboarding date.
# MAGIC - **The disable is gated** — report-only, then one test user confirmed in the console, then the full list, with a safelist and a read-back (`active=false`) check on every call. A valid user would have to have no recognized login in the window *and* pass all three gates.
# MAGIC
# MAGIC **The one false-positive path is a login that is not being counted.** If your single sign-on records sign-ins under an action not in `LOGIN_ACTIONS`, those users look inactive. Run Cell 2, confirm your account's login and provisioning actions, and update the configuration before trusting the candidates. `oidcTokenAuthorization` is excluded by design (it fires on every API call and conflates service principals); if any users are active only through OIDC API calls, the report-only review and spot-check (Cells 3-4) catch them.

# COMMAND ----------

# MAGIC %md ## Configuration: set these for your account

# COMMAND ----------

HOST          = "https://accounts.cloud.databricks.com"   # Azure: https://accounts.azuredatabricks.net
ACCOUNT_ID    = "<account-id>"
SECRET_SCOPE  = "identity-admin"
CLIENT_ID_KEY = "account-sp-client-id"
CLIENT_SECRET_KEY = "account-sp-client-secret"

CATALOG = "your_catalog"      # a catalog/schema you can write to
SCHEMA  = "identity"

INACTIVITY_DAYS     = 90       # disable after this many days of no activity
LOGIN_LOOKBACK_DAYS = 100      # login scan window; must be > INACTIVITY_DAYS

# Confirm these against Cell 2's output for your account, then edit if needed.
PROVISIONING_ACTIONS = ["add", "createUser"]
LOGIN_ACTIONS        = ["login", "tokenLogin", "samlLogin", "oidcBrowserLogin",
                        "jwtLogin", "mfaLogin", "certLogin"]

# Accounts that must NEVER be disabled (break-glass admins, service / integration users).
SAFELIST = {"breakglass@youragency.gov.sg", "integration@youragency.gov.sg"}

assert LOGIN_LOOKBACK_DAYS > INACTIVITY_DAYS, "LOGIN_LOOKBACK_DAYS must exceed INACTIVITY_DAYS"
USERS_TABLE      = f"{CATALOG}.{SCHEMA}.users"
CANDIDATES_TABLE = f"{CATALOG}.{SCHEMA}.inactive_candidates"
spark.sql(f"CREATE SCHEMA IF NOT EXISTS {CATALOG}.{SCHEMA}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Build the active-user roster
# MAGIC Reads the current active users from the Account Users API via the SDK (auto-paginates) and writes them to a reference table.
# MAGIC `overwrite` is intentional: this is a derived table, rebuilt each run; it writes no source data.

# COMMAND ----------

from databricks.sdk import AccountClient

a = AccountClient(
    host=HOST,
    account_id=ACCOUNT_ID,
    client_id=dbutils.secrets.get(SECRET_SCOPE, CLIENT_ID_KEY),
    client_secret=dbutils.secrets.get(SECRET_SCOPE, CLIENT_SECRET_KEY),
)

users = [(u.user_name.lower(), u.id) for u in a.users.list() if u.active]
print(f"{len(users)} active users")

(spark.createDataFrame(users, "email STRING, user_id STRING")
      .write.mode("overwrite").saveAsTable(USERS_TABLE))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Confirm action names and audit span
# MAGIC Note your **provisioning** action (commonly `add`, or `createUser` with automatic identity management) and your **login** actions, and update the configuration cell if they differ.
# MAGIC Also check `earliest`: if your audit history is under 90 days, see the notes at the end (the floor will under-count older users).

# COMMAND ----------

display(spark.sql("""
SELECT action_name, COUNT(*) AS events, MIN(event_time) AS earliest, MAX(event_time) AS latest
FROM system.access.audit
WHERE service_name = 'accounts'
GROUP BY action_name
ORDER BY events DESC
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 3. Find inactive users (report-only)
# MAGIC Joins the roster to last-login and onboarding signals from the audit table and flags anyone inactive for `INACTIVITY_DAYS`+.
# MAGIC Never-logged-in users are baselined on their onboarding date, or on the start of audit history when no onboarding event exists.
# MAGIC This writes a candidate table for review; it disables nothing.

# COMMAND ----------

prov_in  = ", ".join(f"'{x}'" for x in PROVISIONING_ACTIONS)
login_in = ", ".join(f"'{x}'" for x in LOGIN_ACTIONS)

candidates = spark.sql(f"""
WITH audit_start AS (
  SELECT MIN(event_time) AS ts FROM system.access.audit WHERE service_name = 'accounts'
),
onboarded AS (
  SELECT lower(request_params['targetUserName']) AS email, MIN(event_time) AS onboarded_ts
  FROM system.access.audit
  WHERE service_name = 'accounts' AND workspace_id = '0'      -- workspace_id is STRING; '0' = account level
    AND action_name IN ({prov_in})
    AND request_params['targetUserName'] LIKE '%@%'           -- humans only (exclude service principals)
  GROUP BY 1
),
last_login AS (
  SELECT lower(user_identity.email) AS email, MAX(event_time) AS last_login_ts
  FROM system.access.audit
  WHERE service_name = 'accounts'
    AND event_date >= CURRENT_DATE() - INTERVAL {LOGIN_LOOKBACK_DAYS} DAYS   -- partition pruning
    AND action_name IN ({login_in})
    AND response.status_code = 200
    AND user_identity.email LIKE '%@%'
  GROUP BY 1
)
SELECT
  u.email,
  u.user_id,
  ll.last_login_ts,
  o.onboarded_ts,
  (ll.last_login_ts IS NULL) AS never_logged_in,
  COALESCE(ll.last_login_ts, o.onboarded_ts, (SELECT ts FROM audit_start)) AS effective_last_activity,
  DATEDIFF(CURRENT_DATE(), COALESCE(ll.last_login_ts, o.onboarded_ts, (SELECT ts FROM audit_start))) AS days_inactive
FROM {USERS_TABLE} u
LEFT JOIN last_login ll ON u.email = ll.email
LEFT JOIN onboarded   o  ON u.email = o.email
WHERE DATEDIFF(CURRENT_DATE(), COALESCE(ll.last_login_ts, o.onboarded_ts, (SELECT ts FROM audit_start))) >= {INACTIVITY_DAYS}
""")

candidates.write.mode("overwrite").saveAsTable(CANDIDATES_TABLE)
print(f"{candidates.count()} candidates flagged")
display(candidates)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 4. Validate before disabling
# MAGIC How many never-logged-in candidates have a real onboarding event versus rely on the audit-history floor.
# MAGIC If most rely on the floor, confirm your audit span is well past `INACTIVITY_DAYS` (or bring in the identity-provider / HR onboarding date, see notes). Spot-check a few rows against the account console before proceeding.

# COMMAND ----------

display(spark.sql(f"""
SELECT (onboarded_ts IS NOT NULL) AS has_onboarding_event,
       COUNT(*) AS n,
       MIN(effective_last_activity) AS earliest,
       MAX(effective_last_activity) AS latest
FROM {CANDIDATES_TABLE}
WHERE never_logged_in
GROUP BY 1
"""))

# COMMAND ----------

# MAGIC %md
# MAGIC ## 5. Disable the flagged users
# MAGIC **This is the only step that changes anything.** It stays in dry-run until you set `DRY_RUN = False`, and acts on a single user until you set `TEST_ONE = False`.
# MAGIC Always run Cells 3-4 and review the list first. Never disable a list you have not inspected.

# COMMAND ----------

import requests

DRY_RUN  = True   # set False only after reviewing the candidate list
TEST_ONE = True   # True = act on only the first user, as a live test

TOKEN = requests.post(
    f"{HOST}/oidc/accounts/{ACCOUNT_ID}/v1/token",
    auth=(dbutils.secrets.get(SECRET_SCOPE, CLIENT_ID_KEY),
          dbutils.secrets.get(SECRET_SCOPE, CLIENT_SECRET_KEY)),
    data={"grant_type": "client_credentials", "scope": "all-apis"},
).json()["access_token"]

body = {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{"op": "replace", "path": "active", "value": [{"value": "false"}]}],
}

safelist = {e.lower() for e in SAFELIST}
rows = spark.table(CANDIDATES_TABLE).collect()
targets = [(r["email"], r["user_id"]) for r in rows if r["email"] not in safelist]
if TEST_ONE:
    targets = targets[:1]

for email, uid in targets:
    if DRY_RUN:
        print(f"[dry-run] would disable {email} ({uid})")
        continue
    resp = requests.patch(
        f"{HOST}/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/Users/{uid}",
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/scim+json"},
        json=body,
    )
    # Confirm the user is actually inactive, not just that the call returned 200.
    check = requests.get(
        f"{HOST}/api/2.1/accounts/{ACCOUNT_ID}/scim/v2/Users/{uid}",
        headers={"Authorization": f"Bearer {TOKEN}"},
    ).json()
    print(f"{email}: patch={resp.status_code} active={check.get('active')}")

# To reactivate a user, send the same PATCH with "value": "true".

# COMMAND ----------

# MAGIC %md
# MAGIC ## Notes and edge cases
# MAGIC - **Short audit history.** `system.access.audit` is forward-only (365-day retention). A user provisioned before your history began has no onboarding event and is baselined on the start of audit history; they flag only once that span passes 90 days. Until then, cover earlier users with audit log delivery files (full history, if configured) or the identity-provider / HR onboarding date.
# MAGIC - **What counts as activity.** `tokenLogin` is included, so personal-access-token use counts as activity. For interactive-login-only, remove `tokenLogin` from `LOGIN_ACTIONS`, but note that disabling a token-only user also stops their automation. `oidcTokenAuthorization` is deliberately excluded: it fires on every API call and would mask inactivity.
# MAGIC - **Re-provisioned users.** The onboarding date is the earliest provisioning event in the window, so a removed-and-re-added user reflects the re-add date.
# MAGIC - **Authentication.** The service principal must hold the **account admin** role for the Account Users API and the disable call.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Alternative: intranet / PrivateLink (no access to the account host)
# MAGIC If this environment cannot reach `accounts.cloud.databricks.com` (for example, PrivateLink-only with no internet egress), use the **workspace-hosted account SCIM endpoint** `{workspace-url}/api/2.0/account/scim/v2/`, reached over front-end PrivateLink. It exposes the same account-level Users and Groups, so only the roster (Cell 1) and the disable (Cell 5) change; the audit queries (Cells 2-4) are unchanged.
# MAGIC
# MAGIC **Auth (set up from workspace admin settings):** create a service principal under Settings -> Identity and access -> Service principals, grant it Admin access (workspace admin), and generate an OAuth secret on its Secrets tab (the Application Id is the client ID). Authenticate with OAuth client credentials at `{workspace-url}/oidc/v1/token` (OAuth is preferred over personal access tokens). Set `WORKSPACE_URL`, then use the two cells below in place of Cells 1 and 5.
# MAGIC
# MAGIC **Notes:**
# MAGIC - Deactivation through `{workspace-url}/api/2.0/account/scim/v2/Users/{id}` (`PATCH active=false`) applies across the account and all workspaces, which is what CAM needs.
# MAGIC - Requires an identity-federated workspace, the default for new workspaces and most existing ones.
# MAGIC - On a non-critical user, validate that the deactivation behaves account-wide before automating, and confirm the printed count matches your account total.

# COMMAND ----------

# Alternative roster: workspace-hosted account SCIM over PrivateLink (no account host)
import requests

WORKSPACE_URL = "https://<your-workspace>.cloud.databricks.com"
# OAuth M2M for the service principal against the WORKSPACE token endpoint (SP must be a workspace admin here)
ws_token = requests.post(
    f"{WORKSPACE_URL}/oidc/v1/token",
    auth=(dbutils.secrets.get(SECRET_SCOPE, CLIENT_ID_KEY),
          dbutils.secrets.get(SECRET_SCOPE, CLIENT_SECRET_KEY)),
    data={"grant_type": "client_credentials", "scope": "all-apis"},
).json()["access_token"]
WS_HEADERS = {"Authorization": f"Bearer {ws_token}"}

users, start = [], 1
while True:
    page = requests.get(
        f"{WORKSPACE_URL}/api/2.0/account/scim/v2/Users",
        headers=WS_HEADERS,
        params={"startIndex": start, "count": 100, "attributes": "userName,active,id"},
    ).json().get("Resources", [])
    if not page:
        break
    for u in page:
        if u.get("active", True):
            users.append((u.get("userName", "").lower(), u.get("id")))
    start += len(page)

print(f"{len(users)} active users")  # confirm this matches your account total
(spark.createDataFrame(users, "email STRING, user_id STRING")
      .write.mode("overwrite").saveAsTable(USERS_TABLE))

# COMMAND ----------

# Alternative disable: workspace-hosted account SCIM over PrivateLink (no account host)
# Same gating as Cell 5; only the base URL and auth differ. Deactivation applies account-wide.
import requests

DRY_RUN  = True
TEST_ONE = True
WORKSPACE_URL = "https://<your-workspace>.cloud.databricks.com"
ws_token = requests.post(
    f"{WORKSPACE_URL}/oidc/v1/token",
    auth=(dbutils.secrets.get(SECRET_SCOPE, CLIENT_ID_KEY),
          dbutils.secrets.get(SECRET_SCOPE, CLIENT_SECRET_KEY)),
    data={"grant_type": "client_credentials", "scope": "all-apis"},
).json()["access_token"]

body = {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [{"op": "replace", "path": "active", "value": [{"value": "false"}]}],
}
safelist = {e.lower() for e in SAFELIST}
rows = spark.table(CANDIDATES_TABLE).collect()
targets = [(r["email"], r["user_id"]) for r in rows if r["email"] not in safelist]
if TEST_ONE:
    targets = targets[:1]

for email, uid in targets:
    if DRY_RUN:
        print(f"[dry-run] would disable {email} ({uid})")
        continue
    resp = requests.patch(
        f"{WORKSPACE_URL}/api/2.0/account/scim/v2/Users/{uid}",
        headers={"Authorization": f"Bearer {ws_token}", "Content-Type": "application/scim+json"},
        json=body,
    )
    check = requests.get(
        f"{WORKSPACE_URL}/api/2.0/account/scim/v2/Users/{uid}",
        headers={"Authorization": f"Bearer {ws_token}"},
    ).json()
    print(f"{email}: patch={resp.status_code} active={check.get('active')}")
