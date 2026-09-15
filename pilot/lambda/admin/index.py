"""Governance admin console — API + static UI in one Lambda (Function URL).

WHAT THIS SERVES
----------------
  GET  /                        the single-page admin UI (no build step, no CDN)
  GET  /api/meta                pool/client ids, for the login form (unauthenticated)
  GET  /api/config              all governance policy rows
  PUT  /api/config              upsert one policy row
  DELETE /api/config            delete one policy row
  GET  /api/stats               statistics, resolved outcomes, spend, rate counters,
                                break-glass state. Accepts ?user= &group= &minutes= &q=
  GET  /api/identities          Cognito users + groups, for the scope pickers
  GET  /api/models              model inventory from the pricing table
  GET  /api/guardrails          list guardrails, or ?id=<id> for a config preview
  GET  /api/effective           ?username=<u> -> which models that user can reach,
                                and which rule decided each
  GET  /api/diagnostics/spans   gateway OTEL spans. OPT-IN, not a headline statistic —
                                see the note on /api/stats

HOW IT IS EXPOSED
-----------------
Behind an **API Gateway HTTP API**. The function itself is NOT publicly invokable.

A Lambda **Function URL** was the first design and was removed: `authType=NONE`
requires a resource policy with `Principal: "*"`, which made this function
world-accessible and was flagged by account security tooling. (It did not work in
that account anyway — an organization guardrail rejects unauthenticated Function
URLs.) A synth-time CDK Aspect (`pilot/guards.py`) now fails the build on any
wildcard Lambda principal or unauthenticated Function URL so it cannot regress.

The rule worth remembering: *"the endpoint is public but every route checks a
token"* is NOT the same as *"the function is not publicly invokable"*. The public
surface must be API Gateway or CloudFront, never the Lambda.

AUTHENTICATION (and its honest caveat)
--------------------------------------
There is deliberately **no API Gateway JWT authorizer**. Cognito access tokens
carry no `aud` claim, which makes them awkward for the built-in authorizer, so
**every `/api/*` call is authorized in code:**

  1. The caller's Cognito **access token** is passed to `cognito-idp:GetUser`. If
     Cognito accepts it, the token is valid, unexpired and issued by our pool —
     which avoids hand-rolling JWKS signature verification.
  2. The resolved username is then checked for membership of the admin group via
     `AdminListGroupsForUser`, using the Lambda's own role.

The UI shell is public; the data is not. For production, front this with
CloudFront + WAF and use the Cognito hosted UI with authorization-code + PKCE
rather than the password flow the demo uses for convenience.
"""
import json
import os
import time
import urllib.parse

import boto3
from botocore.config import Config as BotoConfig
from botocore import UNSIGNED

_REGION = os.environ.get("AWS_REGION", "us-east-1")
_CONFIG_TABLE = os.environ["CONFIG_TABLE"]
_LEDGER_TABLE = os.environ.get("COST_LEDGER_TABLE", "")
_USER_POOL_ID = os.environ["USER_POOL_ID"]
_CLIENT_ID = os.environ["USER_POOL_CLIENT_ID"]
_ADMIN_GROUP = os.environ.get("ADMIN_GROUP", "gateway-admins")
_GATEWAY_ID = os.environ.get("GATEWAY_ID", "")
_SPANS_LOG_GROUP = os.environ.get("SPANS_LOG_GROUP", "aws/spans")

# The console's history horizon. Statistics is computed entirely from DECISION# records,
# so when they are reaped the tab goes empty — indistinguishable, to the admin, from a
# system that recorded nothing. The UI therefore has to STATE this window and must not
# offer a range longer than it. See config.DECISION_RECORD_TTL_SECONDS.
_DECISION_TTL = int(os.environ.get("DECISION_RECORD_TTL_SECONDS", "86400") or 86400)
# Where the durable copy lives, for the "anything older than the window" hand-off.
_AUDIT_LOG_GROUP = os.environ.get("AUDIT_LOG_GROUP", "")
_AUDIT_LOG_RETENTION_DAYS = os.environ.get("AUDIT_LOG_RETENTION_DAYS", "")

_PRICING_TABLE = os.environ.get("PRICING_TABLE", "")
# The canonical model ids this deployment routes to, on BOTH surfaces. These are the
# strings a MODELS glob is actually matched against — see _model_inventory() for why
# that is not the same as the pricing table's normalized keys.
_GOVERNED_MODEL_IDS = os.environ.get("GOVERNED_MODEL_IDS", "")

_ddb = boto3.client("dynamodb", region_name=_REGION)
_idp = boto3.client("cognito-idp", region_name=_REGION)
_logs = boto3.client("logs", region_name=_REGION)
_bedrock = boto3.client("bedrock", region_name=_REGION)
# Token validation uses the caller's own token, so it must be UNSIGNED (no AWS creds).
_idp_public = boto3.client(
    "cognito-idp", region_name=_REGION, config=BotoConfig(signature_version=UNSIGNED)
)

# RATELIMIT was missing here, which is the whole reason the console had no rate-limit
# screen: the backend rejected the kind, so the UI could not have written one.
VALID_KINDS = ("MODELS", "RATELIMIT", "BUDGET", "GUARDRAIL")
# Read-only in the console. Editing enforcement-off from a web UI should be a deliberate
# CLI act, but an admin must be able to SEE that it is on — see _breakglass().
READONLY_KINDS = ("BREAKGLASS",)


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
def _authorize(event) -> dict:
    """Return {ok, username, error}. Requires a valid token AND admin group."""
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    auth = headers.get("authorization", "")
    if not auth:
        return {"ok": False, "error": "missing Authorization header"}
    token = auth.split()[-1]

    try:
        who = _idp_public.get_user(AccessToken=token)
        username = who["Username"]
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"invalid token: {type(exc).__name__}"}

    try:
        groups = _idp.admin_list_groups_for_user(
            UserPoolId=_USER_POOL_ID, Username=username
        )
        names = [g["GroupName"] for g in groups.get("Groups", [])]
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"group lookup failed: {exc}"}

    if _ADMIN_GROUP not in names:
        return {"ok": False, "error": f"user '{username}' is not in {_ADMIN_GROUP}"}
    return {"ok": True, "username": username, "groups": names}


# --------------------------------------------------------------------------- #
# config CRUD
# --------------------------------------------------------------------------- #
def _to_plain(item: dict) -> dict:
    out = {}
    for k, v in item.items():
        if "S" in v:
            out[k] = v["S"]
        elif "N" in v:
            out[k] = float(v["N"])
        elif "BOOL" in v:
            out[k] = v["BOOL"]
        elif "L" in v:
            out[k] = [x.get("S", "") for x in v["L"]]
    return out


def _list_config() -> list:
    items, kwargs = [], {"TableName": _CONFIG_TABLE}
    while True:
        page = _ddb.scan(**kwargs)
        items.extend(_to_plain(i) for i in page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return sorted(items, key=lambda x: (x.get("pk", ""), x.get("sk", "")))


def _put_config(body: dict) -> dict:
    pk, sk = body.get("pk"), body.get("sk")
    if not pk or sk not in VALID_KINDS:
        return {"error": f"pk required and sk must be one of {VALID_KINDS}"}

    item = {"pk": {"S": pk}, "sk": {"S": sk}}
    if sk == "MODELS":
        item["allow"] = {"L": [{"S": g} for g in (body.get("allow") or [])]}
        item["deny"] = {"L": [{"S": g} for g in (body.get("deny") or [])]}
    elif sk == "RATELIMIT":
        item["tokens_per_window"] = {"N": str(int(body.get("tokens_per_window", 0)))}
        item["requests_per_window"] = {"N": str(int(body.get("requests_per_window", 0)))}
        item["window_seconds"] = {"N": str(int(body.get("window_seconds", 60)))}
        # `pooled` is the whole point of this kind, so it must be written explicitly.
        # Absent, the interceptor defaults it by scope (GROUP# pooled, else per-user),
        # which is a reasonable default but not something to leave implicit from a UI.
        item["pooled"] = {"BOOL": bool(body.get("pooled", False))}
    elif sk == "BUDGET":
        item["budget_usd"] = {"N": str(float(body.get("budget_usd", 0)))}
        item["window_seconds"] = {"N": str(int(body.get("window_seconds", 60)))}
    elif sk == "GUARDRAIL":
        item["guardrail_id"] = {"S": str(body.get("guardrail_id", ""))}
        # The version is part of the SELECTION, not an incidental detail. One id serves a
        # mutable DRAFT and any number of published versions with different content
        # policies, so binding an id alone does not say what will be enforced. The
        # interceptor used to take the version from its own env var — baked from the
        # guardrail CDK created — which was silently wrong for every other guardrail the
        # picker can now reach. DRAFT is the default because it is the one version every
        # guardrail is guaranteed to have.
        item["guardrail_version"] = {
            "S": str(body.get("guardrail_version") or "DRAFT")}
        item["enabled"] = {"BOOL": bool(body.get("enabled", True))}

    _ddb.put_item(TableName=_CONFIG_TABLE, Item=item)
    return {"ok": True, "written": _to_plain(item)}


def _delete_config(body: dict) -> dict:
    pk, sk = body.get("pk"), body.get("sk")
    if not pk or not sk:
        return {"error": "pk and sk required"}
    if pk == "DEFAULT":
        # Removing a DEFAULT row silently disables that control for everyone who
        # has no more specific scope. Refuse rather than allow a quiet weakening.
        return {"error": "refusing to delete a DEFAULT row (edit it instead)"}
    _ddb.delete_item(TableName=_CONFIG_TABLE, Key={"pk": {"S": pk}, "sk": {"S": sk}})
    return {"ok": True}


# --------------------------------------------------------------------------- #
# stats
# --------------------------------------------------------------------------- #
def _ledger_scan() -> list:
    if not _LEDGER_TABLE:
        return []
    items, kwargs = [], {"TableName": _LEDGER_TABLE}
    while True:
        page = _ddb.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return items


def _spend(items: list) -> list:
    """Per-user spend rows (pk = '<sub>#<window>').

    The ledger table is shared by four record kinds, so this must skip the other three
    explicitly rather than assume anything without a known prefix is a spend counter:
      DECISION#  per-request governance decisions
      PENDING#   request-side reservations awaiting reconciliation
      RATE#      rate-limit counters (added when rate limiting moved into the
                 interceptor) — these carry `tokens`/`requests`, not `spend`, and
                 counting them as spend rows produced phantom $0 users.
    """
    skip = ("DECISION#", "PENDING#", "RATE#", "SEEN#")
    rows = []
    for it in items:
        pk = it.get("pk", {}).get("S", "")
        if pk.startswith(skip):
            continue
        sub, _, window = pk.partition("#")
        rows.append({
            "sub": sub,
            "window": window,
            "spend_usd": float(it.get("spend", {}).get("N", 0)),
        })
    rows.sort(key=lambda r: r["window"], reverse=True)
    return rows[:100]


def _rate_counters(items: list) -> list:
    """Live rate-limit counters, so the console can show pooled vs per-user allowances.

    `RATE#GROUP#<g>#<bucket>` is a POOLED counter shared by the group;
    `RATE#USER#<sub>#<bucket>` is one person's. Showing both side by side is the only
    way an admin can see that pooling is actually in effect.
    """
    rows = []
    for it in items:
        pk = it.get("pk", {}).get("S", "")
        if not pk.startswith("RATE#"):
            continue
        rest = pk[len("RATE#"):]
        subject, _, bucket = rest.rpartition("#")
        rows.append({
            "subject": subject,
            "pooled": subject.startswith("GROUP#"),
            "bucket": bucket,
            "tokens": int(float(it.get("tokens", {}).get("N", 0))),
            "requests": int(float(it.get("requests", {}).get("N", 0))),
        })
    rows.sort(key=lambda r: r["bucket"], reverse=True)
    return rows[:60]


def _decisions(items: list, filters: dict | None = None) -> dict:
    """Per-request governance decisions — the ONLY complete record, and now a CORRECT one.

    Interceptor short-circuit responses are not emitted as gateway spans, so
    span-derived counts undercount denials. These records also carry the end-user
    identity and model, which spans structurally lack.

    ⚠️ THE OUTCOME CORRECTION. The request interceptor runs BEFORE the Cedar policy
    engine, so its own record cannot know what the caller finally received. A request the
    interceptor allowed can still be refused by Cedar, and the raw decision row keeps
    saying `allowed / 200`. Measured:

        carol  decision=allowed status=200  ->  caller actually received 403

    Counting that as an allowed request is how this console under-reported denials. The
    RESPONSE interceptor now stamps `final_status` / `final_layer` onto the row, and every
    figure below is computed from the RESOLVED outcome, not the request-stage verdict.

    Rows carry both, so the UI can show *"allowed by interceptor -> denied by Cedar"*
    rather than hiding the correction.
    """
    rows = []
    for it in items:
        if not it.get("pk", {}).get("S", "").startswith("DECISION#"):
            continue
        req_status = int(float(it.get("status", {}).get("N", 0)))
        decision = it.get("decision", {}).get("S", "?")
        has_final = "final_status" in it
        final_status = (int(float(it["final_status"]["N"])) if has_final else req_status)
        final_layer = it.get("final_layer", {}).get("S", "")
        if not final_layer:
            final_layer = "interceptor" if req_status >= 400 else "none"

        # What actually happened to this request, in one field.
        if final_status >= 400 and req_status < 400:
            effective = (f"denied_by_{final_layer}" if final_layer not in ("", "none")
                         else "denied_downstream")
        else:
            effective = decision

        rows.append({
            "ts": int(float(it.get("ts", {}).get("N", 0))),
            "username": it.get("username", {}).get("S", "?"),
            "groups": [g.get("S", "") for g in it.get("groups", {}).get("L", [])],
            "model": it.get("model", {}).get("S", "?"),
            "path": it.get("path", {}).get("S", ""),
            # The interceptor's own verdict, kept so the correction is visible.
            "decision": decision,
            "status": req_status,
            # The resolved truth.
            "effective": effective,
            "final_status": final_status,
            "final_layer": final_layer,
            "corrected": bool(has_final and final_status != req_status),
            "scope": it.get("scope", {}).get("S", ""),
            # Present only after the RESPONSE interceptor reconciled actual usage.
            "input_tokens": int(float(it.get("input_tokens", {}).get("N", 0))),
            "output_tokens": int(float(it.get("output_tokens", {}).get("N", 0))),
            "cost_usd": float(it.get("cost_usd", {}).get("N", 0)),
            "est_cost_usd": float(it.get("est_cost_usd", {}).get("N", 0)),
        })
    rows.sort(key=lambda r: r["ts"], reverse=True)

    # ---- filters -----------------------------------------------------------
    f = filters or {}
    since = int(f.get("minutes") or 0) * 60
    cutoff = int(time.time()) - since if since else 0
    want_user = (f.get("user") or "").strip().lower()
    want_group = (f.get("group") or "").strip().lower()
    q = (f.get("q") or "").strip().lower()

    def keep(r):
        if cutoff and r["ts"] < cutoff:
            return False
        if want_user and r["username"].lower() != want_user:
            return False
        if want_group and want_group not in [g.lower() for g in r["groups"]]:
            return False
        if q:
            hay = " ".join([
                r["username"], r["model"], r["path"], r["decision"],
                r["effective"], r["scope"], r["final_layer"], str(r["final_status"]),
            ]).lower()
            if q not in hay:
                return False
        return True

    matched = [r for r in rows if keep(r)]

    # ---- aggregates, computed from the RESOLVED outcome --------------------
    by_effective, by_user, by_model, by_layer = {}, {}, {}, {}
    tok_in = tok_out = 0
    cost_total = 0.0
    per_user_cost = {}
    denied = corrected = 0
    for r in matched:
        by_effective[r["effective"]] = by_effective.get(r["effective"], 0) + 1
        by_user[r["username"]] = by_user.get(r["username"], 0) + 1
        by_model[r["model"]] = by_model.get(r["model"], 0) + 1
        if r["final_status"] >= 400:
            denied += 1
            by_layer[r["final_layer"]] = by_layer.get(r["final_layer"], 0) + 1
        if r["corrected"]:
            corrected += 1
        tok_in += r["input_tokens"]
        tok_out += r["output_tokens"]
        cost_total += r["cost_usd"]
        per_user_cost[r["username"]] = per_user_cost.get(r["username"], 0.0) + r["cost_usd"]
    total_tok = tok_in + tok_out
    return {
        "total": len(matched),
        "total_unfiltered": len(rows),
        "denied": denied,
        "allowed": len(matched) - denied,
        # How many rows the request-stage verdict would have got WRONG. Surfaced so the
        # correction is auditable rather than invisible.
        "corrected": corrected,
        "by_effective": by_effective,
        "by_denied_layer": by_layer,
        "by_user": by_user,
        "by_model": by_model,
        # True usage, only obtainable from the RESPONSE interceptor.
        "input_tokens": tok_in,
        "output_tokens": tok_out,
        "output_share_pct": round(100.0 * tok_out / total_tok, 1) if total_tok else 0.0,
        "cost_usd": round(cost_total, 6),
        "cost_by_user": {k: round(v, 6) for k, v in per_user_cost.items()},
        "reconciled": sum(1 for r in matched if r["output_tokens"] > 0),
        "rows": matched[:200],
    }


# --------------------------------------------------------------------------- #
# pickers — real identities, real models, real guardrails
# --------------------------------------------------------------------------- #
def _identities() -> dict:
    """Cognito users and groups, so scope is a CHOICE rather than a typed string.

    A free-text scope box accepts `GROUP#ml-reserch` without complaint and produces a
    rule that silently never matches — the worst class of governance bug, because the
    console shows policy that does not exist.
    """
    out = {"users": [], "groups": [], "error": None}
    try:
        pager = _idp.get_paginator("list_users")
        for page in pager.paginate(UserPoolId=_USER_POOL_ID, Limit=60):
            for u in page.get("Users", []):
                out["users"].append({"username": u.get("Username", "")})
        gp = _idp.get_paginator("list_groups")
        for page in gp.paginate(UserPoolId=_USER_POOL_ID, Limit=60):
            for g in page.get("Groups", []):
                out["groups"].append({"name": g.get("GroupName", ""),
                                      "description": g.get("Description", "")})
        out["users"].sort(key=lambda x: x["username"])
        out["groups"].sort(key=lambda x: x["name"])
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"identity lookup failed: {str(exc)[:200]}"
    return out


def _model_inventory(ledger_items: list | None = None) -> dict:
    """The model ids a glob is actually matched against.

    ⚠️ THIS DISTINCTION IS LOAD-BEARING, and getting it wrong made the first version of
    the effective-access preview report the opposite of the truth.

    The pricing table is keyed on a NORMALIZED `model_key` with all punctuation stripped
    (`claudeopus5`), because one row has to serve every cross-region variant. But the
    interceptor matches `MODELS` globs against the model id it resolved from the REQUEST
    (`bedrockprov/anthropic.claude-opus-5`, `us.anthropic.claude-opus-5`). So the shipped
    deny glob `*claude-opus*` matches the request id and does NOT match the pricing key —
    evaluating globs against pricing keys reported opus as *allowed* for a user who is
    in fact denied it.

    So the glob targets come from two honest sources instead:
      * `configured` — the canonical ids this deployment actually routes to, passed in
        from CDK, on both surfaces.
      * `observed`   — distinct model ids seen in real decision records. This grows to
        cover whatever callers actually send, which is the set that matters.

    `priced` is returned separately and clearly labelled: useful for showing rates, never
    for glob matching.
    """
    out = {"configured": [], "observed": [], "priced": [], "error": None}

    out["configured"] = [m for m in
                         (x.strip() for x in _GOVERNED_MODEL_IDS.split(",")) if m]

    seen = set()
    for it in (ledger_items or []):
        if not it.get("pk", {}).get("S", "").startswith("DECISION#"):
            continue
        mid = it.get("model", {}).get("S", "")
        if mid and mid != "?":
            seen.add(mid)
    out["observed"] = sorted(seen)

    if _PRICING_TABLE:
        try:
            kwargs = {"TableName": _PRICING_TABLE}
            while True:
                page = _ddb.scan(**kwargs)
                for it in page.get("Items", []):
                    key = it.get("model_key", {}).get("S", "")
                    if not key or key == "_META":
                        continue
                    out["priced"].append({
                        "model_key": key,
                        "input_per_1k": float(it.get("input_per_1k", {}).get("N", 0) or 0),
                        "output_per_1k": float(it.get("output_per_1k", {}).get("N", 0) or 0),
                        "source": it.get("source", {}).get("S", ""),
                    })
                if "LastEvaluatedKey" not in page:
                    break
                kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
            out["priced"].sort(key=lambda m: m["model_key"])
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"pricing scan failed: {str(exc)[:200]}"

    # The list the preview and the picker should use.
    out["glob_targets"] = sorted(set(out["configured"]) | set(out["observed"]))
    return out


def _retention() -> dict:
    """The console's history horizon, and where to go for anything older.

    WHY THIS IS AN API FIELD AND NOT A UI CONSTANT. Statistics is computed entirely from
    `DECISION#` records, so once they hit their TTL the tab is empty — and an empty table
    is indistinguishable, to the person looking at it, from a governance plane that
    recorded nothing. That actually happened: the records lived one hour while the UI
    offered "last 24 hours", so an admin returning after an idle night saw a blank screen
    on a completely healthy system.

    Two things fix that, and both need the real numbers rather than hardcoded prose:
    the UI must not offer a range longer than the window, and when it has nothing to show
    it must say the window has expired and point at the durable copy.

    Also builds the CloudWatch Logs Insights deep link. Constructed here because the URL
    fragment needs the region and log group name, and this is where they are known.
    """
    hours = max(1, _DECISION_TTL // 3600)
    out = {
        "decision_ttl_seconds": _DECISION_TTL,
        "decision_window_hours": hours,
        "decision_window_label": (f"{hours} hour" if hours == 1 else f"{hours} hours"),
        "audit_log_group": _AUDIT_LOG_GROUP,
        "audit_retention_days": _AUDIT_LOG_RETENTION_DAYS,
        "audit_console_url": "",
        "audit_insights_url": "",
        "audit_query": "",
    }
    if not _AUDIT_LOG_GROUP:
        return out

    # A ready-to-run query, so the hand-off lands on the answer rather than a blank editor.
    #
    # Two things here are easy to get wrong and both fail SILENTLY — an empty result set
    # reads as "there is no history", which is worse than no link at all:
    #
    #  1. `audit = 1`, not `audit = true`. The records carry `"audit": true` as a JSON
    #     boolean and Logs Insights surfaces JSON booleans as 0/1. Verified against the live
    #     log: `audit = 1` returned 200 rows, `audit = true` returned 0.
    #  2. Only REQUEST-stage fields are selected. One request produces TWO records, and the
    #     resolved outcome (`final_status`, `final_layer`) is stamped on the RESPONSE one.
    #     Listing those fields against `stage = 'REQUEST'` renders empty columns and invites
    #     the reader to conclude the outcome was never recorded. `request_id` is included
    #     instead, because that is what joins the two stages.
    query = "\n".join([
        "fields @timestamp, username, decision, status, model, path, request_id",
        "| filter audit = 1 and stage = 'REQUEST'",
        "| sort @timestamp desc",
        "| limit 200",
    ])
    out["audit_query"] = query
    # The companion query for the resolved outcome, since it lives on the other stage.
    out["audit_query_outcome"] = "\n".join([
        # One `fields` line, kept explicit so it is not mistaken for two list elements.
        ("fields @timestamp, request_id, status, final_status, final_layer, "
         + "interceptor_allowed"),
        "| filter audit = 1 and stage = 'RESPONSE'",
        "| sort @timestamp desc",
        "| limit 200",
    ])

    # CloudWatch console deep links percent-ENCODE twice inside the fragment: the value is
    # escaped once for the inner object notation and again for the fragment itself. Getting
    # this wrong silently lands the user on an empty Logs Insights page rather than erroring,
    # so it is written out explicitly rather than eyeballed.
    def _enc(s: str) -> str:
        return urllib.parse.quote(s, safe="")

    base = f"https://{_REGION}.console.aws.amazon.com/cloudwatch/home?region={_REGION}"
    out["audit_console_url"] = (
        f"{base}#logsV2:log-groups/log-group/{_enc(_enc(_AUDIT_LOG_GROUP))}")
    out["audit_insights_url"] = (
        f"{base}#logsV2:logs-insights"
        f"$3FqueryDetail$3D~(end~0~start~-86400"
        f"~timeType~'RELATIVE~unit~'seconds"
        f"~editorString~'{_enc(_enc(query))}"
        f"~source~(~'{_enc(_enc(_AUDIT_LOG_GROUP))}))")
    return out


def _version_sort_key(v: str):
    """DRAFT first, then published versions in numeric order."""
    if v == "DRAFT":
        return (0, 0)
    try:
        return (1, int(v))
    except (TypeError, ValueError):
        return (2, 0)


def _guardrail_versions(gid: str) -> list:
    """Every version of ONE guardrail, DRAFT first.

    ⚠️ THE TWO `ListGuardrails` CALLS RETURN DIFFERENT THINGS, and conflating them is why
    the version picker was empty on the first attempt:

        list_guardrails()                          -> one entry per guardrail, DRAFT ONLY.
                                                      Published versions are NOT included.
        list_guardrails(guardrailIdentifier=<id>)  -> one entry PER VERSION of that guardrail.

    Verified against a freshly published version: the unfiltered call still reported only
    `DRAFT`, while the per-identifier call returned `DRAFT` and `1`. So versions can only be
    discovered per guardrail, which is also why this is not folded into `_guardrails()` —
    doing it there would mean one extra API call per guardrail on every page load.

    Degrades to `["DRAFT"]` rather than raising: DRAFT is the version an unversioned binding
    resolves to, so it is the honest floor.
    """
    versions: list = []
    try:
        pager = _bedrock.get_paginator("list_guardrails")
        for page in pager.paginate(guardrailIdentifier=gid):
            for g in page.get("guardrails", []):
                v = g.get("version", "")
                if v and v not in versions:
                    versions.append(v)
    except Exception:  # noqa: BLE001
        return ["DRAFT"]
    versions.sort(key=_version_sort_key)
    if "DRAFT" not in versions:
        versions.insert(0, "DRAFT")
    return versions


def _guardrails() -> dict:
    """Guardrails available to bind, so the id does not have to be pasted from memory.

    Ids and names only. VERSIONS ARE NOT HERE ON PURPOSE — the unfiltered `ListGuardrails`
    cannot see published versions at all (see `_guardrail_versions`), and fetching them would
    cost one additional API call per guardrail on every page load. They come back with the
    per-guardrail detail instead, which the UI already fetches when a guardrail is selected.
    """
    out = {"guardrails": [], "error": None}
    try:
        by_id: dict = {}
        pager = _bedrock.get_paginator("list_guardrails")
        for page in pager.paginate():
            for g in page.get("guardrails", []):
                gid = g.get("id", "")
                if not gid or gid in by_id:
                    continue
                by_id[gid] = {
                    "id": gid,
                    "arn": g.get("arn", ""),
                    "name": g.get("name", ""),
                    "status": g.get("status", ""),
                    "version": g.get("version", ""),
                    "description": g.get("description", ""),
                }
        out["guardrails"] = sorted(by_id.values(), key=lambda g: g["name"])
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"guardrail list failed: {str(exc)[:200]}"
    return out


def _guardrail_detail(gid: str, version: str = "DRAFT") -> dict:
    """What a guardrail actually enforces — so an admin can look before binding.

    Summarised rather than dumped: the counts and the enabled policy names are what
    answer "is this the right guardrail", and the full config is large and noisy.

    ⚠️ The fallback to an unversioned `get_guardrail` is REPORTED, not silent. Previewing
    one version while a different one is enforced is the failure this whole change exists to
    remove, so if the requested version could not be read, `version_fallback` says so and
    the UI shows a warning instead of presenting the wrong policy as if it were the
    right one.
    """
    out = {"id": gid, "error": None, "requested_version": version,
           "version_fallback": False, "version_error": None, "versions": ["DRAFT"]}
    if not gid:
        out["error"] = "no guardrail id"
        return out
    # Returned alongside the detail so the picker can offer real versions without the list
    # endpoint paying an API call per guardrail.
    out["versions"] = _guardrail_versions(gid)
    try:
        g = _bedrock.get_guardrail(guardrailIdentifier=gid, guardrailVersion=version)
    except Exception as vexc:  # noqa: BLE001
        try:
            g = _bedrock.get_guardrail(guardrailIdentifier=gid)
            out["version_fallback"] = True
            out["version_error"] = str(vexc)[:200]
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"get_guardrail failed: {str(exc)[:200]}"
            return out

    cp = g.get("contentPolicy", {}) or {}
    sip = g.get("sensitiveInformationPolicy", {}) or {}
    tp = g.get("topicPolicy", {}) or {}
    wp = g.get("wordPolicy", {}) or {}
    cip = g.get("contextualGroundingPolicy", {}) or {}
    out.update({
        "name": g.get("name", ""),
        "status": g.get("status", ""),
        "version": g.get("version", ""),
        "description": g.get("description", ""),
        "blocked_input_message": g.get("blockedInputMessaging", ""),
        "content_filters": [
            {"type": f.get("type"), "input": f.get("inputStrength"),
             "output": f.get("outputStrength")}
            for f in cp.get("filters", []) or []
        ],
        "pii_entities": [e.get("type") for e in sip.get("piiEntities", []) or []],
        "regexes": [r.get("name") for r in sip.get("regexes", []) or []],
        "topics": [t.get("name") for t in tp.get("topics", []) or []],
        "word_lists": len(wp.get("words", []) or []),
        "managed_word_lists": [w.get("type") for w in
                               wp.get("managedWordLists", []) or []],
        "grounding_filters": [f.get("type") for f in cip.get("filters", []) or []],
    })
    return out


def _effective_access(username: str, config_items: list, model_ids: list,
                      probe: str = "") -> dict:
    """Which models can this user actually reach, and WHICH RULE decided each.

    This is the screen's real question. Reading `allow: *` next to `deny: *claude-opus*`
    and mentally applying most-specific-scope-first precedence is not a reasonable thing
    to ask of an operator, so resolve it here using the same order the interceptor uses:

        USER#<username>  ->  GROUP#<group>  ->  DEFAULT      (first match wins)

    and then evaluate the matched row's globs the same way (deny wins over allow).
    """
    import fnmatch

    out = {"username": username, "scope_chain": [], "resolved_scope": None,
            "allow": [], "deny": [], "models": [], "error": None}
    if not username:
        out["error"] = "no username"
        return out

    groups = []
    try:
        resp = _idp.admin_list_groups_for_user(UserPoolId=_USER_POOL_ID,
                                              Username=username)
        groups = [g["GroupName"] for g in resp.get("Groups", [])]
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"group lookup failed: {str(exc)[:200]}"

    chain = [f"USER#{username}"] + [f"GROUP#{g}" for g in groups] + ["DEFAULT"]
    out["scope_chain"] = chain
    out["groups"] = groups

    by_key = {(i.get("pk"), i.get("sk")): i for i in config_items}
    row = None
    for scope in chain:
        cand = by_key.get((scope, "MODELS"))
        if cand:
            row, out["resolved_scope"] = cand, scope
            break

    if row is None:
        out["error"] = ("no MODELS rule matched any scope in this user's chain — with no "
                        "rule the interceptor's allow list is empty, so nothing is "
                        "entitled")
        return out

    allow = [g for g in (row.get("allow") or []) if g]
    deny = [g for g in (row.get("deny") or []) if g]
    out["allow"], out["deny"] = allow, deny

    def verdict_for(model_id: str) -> dict:
        # Mirrors the interceptor: deny wins, and no allow match is a denial. Matched
        # against the model id AS IT ARRIVES ON THE REQUEST — not a normalized key.
        hit_deny = next((g for g in deny if fnmatch.fnmatch(model_id, g)), None)
        hit_allow = next((g for g in allow if fnmatch.fnmatch(model_id, g)), None)
        if hit_deny:
            return {"model_id": model_id, "verdict": "denied",
                    "reason": f"deny glob {hit_deny}"}
        if hit_allow:
            return {"model_id": model_id, "verdict": "allowed",
                    "reason": f"allow glob {hit_allow}"}
        return {"model_id": model_id, "verdict": "denied",
                "reason": "matched no allow glob"}

    out["models"] = [verdict_for(m) for m in model_ids if m]
    out["models"].sort(key=lambda x: (x["verdict"] != "allowed", x["model_id"]))
    out["allowed_count"] = sum(1 for m in out["models"] if m["verdict"] == "allowed")
    out["denied_count"] = len(out["models"]) - out["allowed_count"]
    # Ad-hoc "would this id be allowed?" test, so an admin can check a model that has
    # not been seen in traffic yet without guessing at glob semantics.
    if probe:
        out["probe"] = verdict_for(probe)
    return out


def _breakglass(config_items: list) -> dict:
    """Is enforcement currently bypassed? The console must never be silent about this."""
    for i in config_items:
        if i.get("pk") == "DEFAULT" and i.get("sk") == "BREAKGLASS":
            return {"enabled": bool(i.get("enabled")),
                    "reason": i.get("reason", ""),
                    "set_by": i.get("set_by", "")}
    return {"enabled": False, "reason": "", "set_by": "", "missing": True}


def _enforcement(minutes: int = 60) -> dict:
    """Enforcement stats from gateway OTEL spans.

    Reminder on the split: spans give WHICH LAYER answered but carry no identity and
    no token counts, so per-user attribution comes from the ledger above, not here.
    """
    # NOTE: attribute names contain dots, so the WHOLE path is backticked. Backticking
    # only the leaf silently returns an empty column.
    query = f"""
fields `attributes.http.response.status_code` as status,
       `attributes.errorType` as layer,
       `attributes.aws.agentcore.gateway.throttle.customer.limit_key` as limitKey,
       `attributes.url.path` as path
| filter `attributes.gateway.id` = "{_GATEWAY_ID}"
| sort @timestamp desc
| limit 200
"""
    out = {"total": 0, "by_status": {}, "by_layer": {}, "by_path": {}, "rows": []}
    try:
        started = _logs.start_query(
            logGroupNames=[_SPANS_LOG_GROUP],
            startTime=int(time.time()) - minutes * 60,
            endTime=int(time.time()),
            queryString=query,
            limit=200,
        )
        # Bounded poll for the async CloudWatch Logs Insights query (max 25 x 1s = 25s).
        for _ in range(25):
            time.sleep(1)  # nosemgrep: arbitrary-sleep -- polling an async query result, bounded above
            res = _logs.get_query_results(queryId=started["queryId"])
            if res["status"] in ("Complete", "Failed", "Cancelled"):
                break
        for row in res.get("results", []):
            r = {f["field"]: f["value"] for f in row if f["field"] != "@ptr"}
            status = r.get("status", "?")
            layer = r.get("layer") or "allowed"
            path = r.get("path", "?")
            out["total"] += 1
            out["by_status"][status] = out["by_status"].get(status, 0) + 1
            out["by_layer"][layer] = out["by_layer"].get(layer, 0) + 1
            out["by_path"][path] = out["by_path"].get(path, 0) + 1
            if len(out["rows"]) < 60:
                out["rows"].append(r)
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"span query failed: {exc}"
    return out


# --------------------------------------------------------------------------- #
# http plumbing
# --------------------------------------------------------------------------- #
def _json(status: int, payload) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization,Content-Type",
            "Access-Control-Allow-Methods": "GET,PUT,DELETE,OPTIONS",
        },
        "body": json.dumps(payload),
    }


def handler(event, context):
    ctx = event.get("requestContext", {}) or {}
    method = (ctx.get("http", {}) or {}).get("method", "GET").upper()
    path = (ctx.get("http", {}) or {}).get("path", "/") or "/"

    if method == "OPTIONS":
        return _json(204, {})

    # The UI shell is public; every /api/* route is authorized below.
    if path in ("/", "/index.html"):
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/html; charset=utf-8",
                        "Cache-Control": "no-store"},
            "body": _UI_HTML.replace("__REGION__", _REGION).replace(
                "__CLIENT_ID__", _CLIENT_ID),
        }

    if not path.startswith("/api/"):
        return _json(404, {"error": "not found"})

    if path == "/api/meta" and method == "GET":
        # Unauthenticated: only non-sensitive values the login form needs.
        return _json(200, {"region": _REGION, "client_id": _CLIENT_ID,
                           "admin_group": _ADMIN_GROUP})

    auth = _authorize(event)
    if not auth["ok"]:
        return _json(401, {"error": auth["error"]})

    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:  # noqa: BLE001
        body = {}

    if path == "/api/config":
        if method == "GET":
            return _json(200, {"items": _list_config()})
        if method == "PUT":
            result = _put_config(body)
            print(f"AUDIT admin={auth['username']} PUT {body.get('pk')}/{body.get('sk')} "
                  f"-> {result}")
            return _json(400 if "error" in result else 200, result)
        if method == "DELETE":
            result = _delete_config(body)
            print(f"AUDIT admin={auth['username']} DELETE "
                  f"{body.get('pk')}/{body.get('sk')} -> {result}")
            return _json(400 if "error" in result else 200, result)

    qs = event.get("queryStringParameters") or {}

    if path == "/api/stats" and method == "GET":
        # Spans are NO LONGER fetched here. They contributed exactly two facts —
        # `errorType=throttle` (a native rate limit fired) and `errorType=user` (Cedar
        # denied) — and both native rate limits have been deleted, so `throttle` can
        # never occur again. The one remaining fact is now resolved from the decision
        # records themselves via the RESPONSE interceptor's outcome stamp, which is both
        # complete and identified. Fetching spans also cost a ~25s Logs Insights poll on
        # every page load. Available on demand at /api/diagnostics/spans.
        ledger = _ledger_scan()
        cfg = _list_config()
        return _json(200, {
            "decisions": _decisions(ledger, {
                "user": qs.get("user"),
                "group": qs.get("group"),
                "minutes": qs.get("minutes"),
                "q": qs.get("q"),
            }),
            "spend": _spend(ledger),
            "rate_counters": _rate_counters(ledger),
            "breakglass": _breakglass(cfg),
            # So the UI can state its own horizon and hand off to the archive instead of
            # rendering an empty table that looks like a fault.
            "retention": _retention(),
        })

    if path == "/api/identities" and method == "GET":
        return _json(200, _identities())

    if path == "/api/models" and method == "GET":
        return _json(200, _model_inventory(_ledger_scan()))

    if path == "/api/guardrails" and method == "GET":
        gid = qs.get("id")
        if gid:
            return _json(200, _guardrail_detail(gid, qs.get("version") or "DRAFT"))
        return _json(200, _guardrails())

    if path == "/api/effective" and method == "GET":
        inv = _model_inventory(_ledger_scan())
        return _json(200, _effective_access(
            qs.get("username") or "", _list_config(),
            inv.get("glob_targets", []), qs.get("probe") or ""))

    if path == "/api/diagnostics/spans" and method == "GET":
        # Opt-in. See the note on /api/stats for why this is not a headline statistic.
        return _json(200, _enforcement(int(qs.get("minutes") or 60)))

    return _json(404, {"error": "not found"})


# --------------------------------------------------------------------------- #
# UI — single file, no build step, no framework
# --------------------------------------------------------------------------- #
_UI_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Inference Governance Console</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2230;--line:#30363d;--tx:#e6edf3;
        --dim:#8b949e;--acc:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;
        --vio:#bc8cff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--tx);
       font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  header{padding:14px 20px;border-bottom:1px solid var(--line);display:flex;
         align-items:center;gap:14px}
  header h1{font-size:15px;margin:0;font-weight:600}
  header .who{margin-left:auto;color:var(--dim);font-size:12px}
  button{background:var(--acc);color:#0d1117;border:0;border-radius:6px;
         padding:7px 13px;font-weight:600;cursor:pointer;font-size:13px}
  button.ghost{background:transparent;color:var(--tx);border:1px solid var(--line)}
  button.danger{background:var(--bad);color:#fff}
  button.sm{padding:4px 9px;font-size:12px}
  button:disabled{opacity:.5;cursor:not-allowed}
  input,select{background:#0d1117;color:var(--tx);border:1px solid var(--line);
               border-radius:6px;padding:7px 9px;font-size:13px;font-family:inherit}
  main{padding:20px;max-width:1240px}
  .tabs{display:flex;gap:6px;margin-bottom:18px;flex-wrap:wrap}
  .tabs button{background:transparent;color:var(--dim);border:1px solid transparent}
  .tabs button.on{color:var(--tx);border-color:var(--line);background:var(--panel)}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
        padding:16px;margin-bottom:16px}
  .card h2{margin:0 0 4px;font-size:14px}
  .card h3{margin:16px 0 6px;font-size:13px}
  .card p.hint{margin:0 0 12px;color:var(--dim);font-size:12px;line-height:1.6}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
        vertical-align:middle}
  th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;
     letter-spacing:.4px}
  code{background:#0d1117;border:1px solid var(--line);border-radius:4px;
       padding:1px 5px;font-size:12px}
  .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
  .pill{font-size:11px;padding:2px 8px;border-radius:20px;border:1px solid var(--line)}
  .ok{color:var(--ok)} .bad{color:var(--bad)} .warn{color:var(--warn)}
  .dim{color:var(--dim)}
  .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}
  .kpis{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px}
  .kpi{background:var(--panel2);border:1px solid var(--line);border-radius:9px;
       padding:10px 14px;min-width:120px}
  .kpi .v{font-size:19px;font-weight:700}
  .kpi .l{font-size:10.5px;color:var(--dim);text-transform:uppercase;
          letter-spacing:.5px;margin-top:2px}
  .note{border-left:3px solid var(--acc);background:#11161f;border-radius:0 8px 8px 0;
        padding:10px 13px;margin:0 0 14px;font-size:12.5px;color:var(--dim);
        line-height:1.6}
  .note b{color:var(--tx)}
  .note.bad{border-left-color:var(--bad)}
  .note.warn{border-left-color:var(--warn)}
  .banner{background:#3d1d1d;border:1px solid var(--bad);border-radius:9px;
          padding:12px 15px;margin:0 0 16px;font-size:13px}
  .banner b{color:#ffb4ab}
  #login{max-width:340px;margin:80px auto;text-align:center}
  #login input{width:100%;margin-bottom:9px}
  #err{color:var(--bad);font-size:12.5px;min-height:18px;margin-top:8px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:900px){.grid2{grid-template-columns:1fr}}
  .scroll{max-height:460px;overflow-y:auto}
  .chips{display:flex;gap:5px;flex-wrap:wrap}
  .chip{font-size:11px;padding:2px 7px;border-radius:5px;background:#0d1117;
        border:1px solid var(--line)}
  .chip.deny{border-color:#5c2a2a;color:#ff9c8f}
  .chip.allow{border-color:#1d4429;color:#7ee787}
  .muted-row{opacity:.55}
</style>
</head>
<body>

<div id="login">
  <h1 style="font-size:16px">Inference Governance Console</h1>
  <p class="dim" style="font-size:12.5px">Sign in with a Cognito user in the
     <code>gateway-admins</code> group.</p>
  <input id="u" placeholder="username" autocomplete="username">
  <input id="p" type="password" placeholder="password" autocomplete="current-password">
  <button onclick="login()" style="width:100%">Sign in</button>
  <div id="err"></div>
</div>

<div id="app" style="display:none">
<header>
  <h1>Inference Governance Console</h1>
  <div class="tabs" style="margin:0">
    <button data-t="access" onclick="tab('access')">Model access</button>
    <button data-t="limits" onclick="tab('limits')">Rate &amp; cost</button>
    <button data-t="guard"  onclick="tab('guard')">Guardrails</button>
    <button data-t="stats"  onclick="tab('stats')">Statistics</button>
  </div>
  <span class="who" id="who"></span>
  <button class="ghost sm" onclick="logout()">Sign out</button>
</header>
<main>
  <div id="bg-banner"></div>
  <div id="view"></div>
</main>
</div>

<script>
const REGION="__REGION__", CLIENT_ID="__CLIENT_ID__";
let TOKEN=sessionStorage.getItem("tok")||"", USER=sessionStorage.getItem("usr")||"";
let CFG=[], IDS={users:[],groups:[]}, MODELS=[], PRICED=[], GUARDS=[], TAB="access";
/* Retention metadata from /api/stats: the console's own history horizon plus where the
   durable copy lives. Defaults match config.DECISION_RECORD_TTL_SECONDS so the first
   render before any fetch is still truthful. */
let RET={decision_ttl_seconds:86400,decision_window_hours:24,
         decision_window_label:"24 hours",audit_log_group:"",
         audit_retention_days:"",audit_insights_url:"",audit_console_url:""};

function show(id){document.getElementById("login").style.display=id==="login"?"":"none";
  document.getElementById("app").style.display=id==="app"?"":"none";}

async function login(){
  const u=document.getElementById("u").value.trim(), p=document.getElementById("p").value;
  const e=document.getElementById("err"); e.textContent="signing in...";
  try{
    const r=await fetch(`https://cognito-idp.${REGION}.amazonaws.com/`,{method:"POST",
      headers:{"Content-Type":"application/x-amz-json-1.1",
               "X-Amz-Target":"AWSCognitoIdentityProviderService.InitiateAuth"},
      body:JSON.stringify({AuthFlow:"USER_PASSWORD_AUTH",ClientId:CLIENT_ID,
        AuthParameters:{USERNAME:u,PASSWORD:p}})});
    const j=await r.json();
    if(!j.AuthenticationResult){e.textContent=j.message||"login failed";return;}
    TOKEN=j.AuthenticationResult.AccessToken; USER=u;
    sessionStorage.setItem("tok",TOKEN); sessionStorage.setItem("usr",u);
    e.textContent=""; boot();
  }catch(x){e.textContent=String(x);}
}
function logout(){sessionStorage.clear();TOKEN="";location.reload();}

async function api(path,opts){
  const r=await fetch("/api"+path,Object.assign({headers:{
    "Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"}},opts||{}));
  if(r.status===401){logout();throw new Error("session expired");}
  return r.json();
}

async function boot(){
  show("app");
  document.getElementById("who").textContent=USER;
  try{
    const [c,i,m,g]=await Promise.all([
      api("/config"), api("/identities"), api("/models"), api("/guardrails")]);
    GUARDS=(g&&g.guardrails)||[];
    CFG=c.items||[]; IDS=i||IDS;
    // Glob targets are REQUEST-shaped model ids. Deliberately not the pricing table's
    // normalized keys: `*claude-opus*` matches `anthropic.claude-opus-5` but NOT
    // `claudeopus5`, so using pricing keys reported the opposite verdict.
    MODELS=(m&&m.glob_targets)||[]; PRICED=(m&&m.priced)||[];
    tab(TAB);
    checkBreakGlass();
  }catch(x){
    document.getElementById("view").innerHTML=
      `<div class="note bad"><b>Could not load.</b> ${esc(String(x))}</div>`;
  }
}

function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,
  c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}

/* Placeholder for an absent value.
   WARNING: THE EM-DASH IS MARKUP, SO IT MUST NOT GO THROUGH esc(). Writing
   esc(value || "&mdash;") escapes the ampersand of the placeholder itself, emitting
   "&amp;mdash;" — which the browser renders as the literal text "&mdash;" in the cell.
   That shipped in eight cells across four tabs. This keeps the DATA escaped while leaving
   the placeholder as the entity it is, so the two cannot be confused again.
   `unit` is appended only when there is a value, so an empty cell reads "—" and not "—s". */
function orDash(v,unit){
  if(v===null||v===undefined||v==="")return "&mdash;";
  return esc(v)+(unit||"");
}
function row(pk,sk){return CFG.find(i=>i.pk===pk&&i.sk===sk);}
function rowsOf(sk){return CFG.filter(i=>i.sk===sk)
  .sort((a,b)=>a.pk==="DEFAULT"?-1:b.pk==="DEFAULT"?1:a.pk.localeCompare(b.pk));}

/* ---------- scope picker: never a free-text box ---------- */
function scopeSelect(id){
  const g=IDS.groups.map(x=>`<option value="GROUP#${esc(x.name)}">GROUP#${esc(x.name)}</option>`).join("");
  const u=IDS.users.map(x=>`<option value="USER#${esc(x.username)}">USER#${esc(x.username)}</option>`).join("");
  return `<select id="${id}">
    <option value="DEFAULT">DEFAULT (everyone)</option>
    ${g?`<optgroup label="Groups">${g}</optgroup>`:""}
    ${u?`<optgroup label="Users">${u}</optgroup>`:""}
  </select>`;
}
function scopeLabel(pk){
  if(pk==="DEFAULT")return `<code>DEFAULT</code> <span class="dim">everyone</span>`;
  if(pk.startsWith("GROUP#"))return `<code>${esc(pk)}</code> <span class="pill">group</span>`;
  if(pk.startsWith("USER#"))return `<code>${esc(pk)}</code> <span class="pill">user</span>`;
  return `<code>${esc(pk)}</code>`;
}

async function put(pk,sk,extra){
  const body=Object.assign({pk:pk,sk:sk},extra);
  const r=await api("/config",{method:"PUT",body:JSON.stringify(body)});
  if(r.error){alert("Save failed: "+r.error);return false;}
  CFG=(await api("/config")).items||[]; return true;
}
async function del(pk,sk){
  if(!confirm(`Delete ${sk} rule for ${pk}?\n\nWith the rule gone, this scope falls through to the next one in the chain (group, then DEFAULT).`))return;
  const r=await api("/config",{method:"DELETE",body:JSON.stringify({pk:pk,sk:sk})});
  if(r.error){alert(r.error);return;}
  CFG=(await api("/config")).items||[]; tab(TAB);
}

/* ---------- break-glass banner ---------- */
async function checkBreakGlass(){
  const bg=row("DEFAULT","BREAKGLASS");
  const el=document.getElementById("bg-banner");
  if(bg&&bg.enabled===true){
    el.innerHTML=`<div class="banner">
      <b>&#9888; ENFORCEMENT IS BYPASSED.</b> The break-glass row is enabled, so the request
      interceptor is allowing every request without evaluating model access, rate limits,
      cost budgets or guardrails. Cedar group authorization still applies.
      <br><br>Set by <code>${esc(bg.set_by||"unknown")}</code> &mdash; reason:
      <i>${esc(bg.reason||"none recorded")}</i>.
      <br><br><span class="dim">Every bypassed request is recorded in the audit log as
      <code>breakglass_bypass</code>. Clear the <code>DEFAULT</code>/<code>BREAKGLASS</code>
      row to restore enforcement; it is intentionally not editable from this console.</span>
    </div>`;
  } else { el.innerHTML=""; }
}

function tab(t){
  TAB=t;
  document.querySelectorAll(".tabs button").forEach(b=>
    b.classList.toggle("on",b.dataset.t===t));
  ({access:viewAccess,limits:viewLimits,guard:viewGuard,stats:viewStats}[t])();
}

/* =======================================================================
   MODEL ACCESS
   ======================================================================= */
function viewAccess(){
  const rows=rowsOf("MODELS").map(r=>{
    const allow=(r.allow||[]).map(g=>`<span class="chip allow">${esc(g)}</span>`).join(" ")||'<span class="dim">none</span>';
    const deny=(r.deny||[]).map(g=>`<span class="chip deny">${esc(g)}</span>`).join(" ")||'<span class="dim">&mdash;</span>';
    return `<tr><td>${scopeLabel(r.pk)}</td><td><div class="chips">${allow}</div></td>
      <td><div class="chips">${deny}</div></td>
      <td style="text-align:right">${r.pk==="DEFAULT"?"":
        `<button class="danger sm" onclick="del('${esc(r.pk)}','MODELS')">Delete</button>`}</td></tr>`;
  }).join("");

  const modelOpts=MODELS.map(m=>`<option value="${esc(m)}">${esc(m)}</option>`).join("");
  const globOpts=['*','*claude-opus*','*claude-sonnet*','us.*']
    .map(g=>`<option value="${esc(g)}">${esc(g)}</option>`).join("");
  const userOpts=IDS.users.map(u=>`<option value="${esc(u.username)}">${esc(u.username)}</option>`).join("");

  document.getElementById("view").innerHTML=`
  <div class="card">
    <h2>How model access is decided</h2>
    <p class="hint">
      Each rule holds two glob lists. For a given request the interceptor finds the
      <b>first scope that has a MODELS rule</b>, walking
      <code>USER#</code> &rarr; <code>GROUP#</code> &rarr; <code>DEFAULT</code>, and then
      evaluates <em>only that rule</em> &mdash; rules do not merge.
      <br><br>
      Within the matched rule: a model must match an <b>allow</b> glob to be permitted, and
      any <b>deny</b> match overrides allow. So <code>allow&nbsp;*</code> with
      <code>deny&nbsp;*claude-opus*</code> reads as <i>"everything except opus"</i>.
      <br><br>
      The shipped policy uses that shape deliberately: <code>DEFAULT</code> denies opus, and
      <code>GROUP#ml-research</code> has its own rule with an empty deny list, so joining
      that group grants opus. One glob covers both Bedrock surfaces &mdash;
      <code>*claude-opus*</code> matches <code>anthropic.claude-opus-5</code> and
      <code>us.anthropic.claude-opus-5</code> alike.
    </p>
    <table><thead><tr><th>Scope</th><th>Allow</th><th>Deny</th><th></th></tr></thead>
      <tbody>${rows||'<tr><td colspan="4" class="dim">no rules</td></tr>'}</tbody></table>
  </div>

  <div class="card">
    <h2>What can this user actually reach?</h2>
    <p class="hint">Resolves the chain above and shows which rule decided each model. This
       is the answer the two glob columns only imply.
       <br><br>
       Globs are matched against the model id <b>as it arrives on the request</b> &mdash;
       e.g. <code>bedrockprov/anthropic.claude-opus-5</code> or
       <code>us.anthropic.claude-opus-5</code> &mdash; so the list below is this
       deployment's configured ids plus every id actually seen in traffic. It is
       <em>not</em> the pricing table's normalized keys: those strip punctuation, and
       <code>*claude-opus*</code> does not match <code>claudeopus5</code>.</p>
    <div class="row">
      <select id="eff-user"><option value="">select a user...</option>${userOpts}</select>
      <input id="eff-probe" placeholder="optional: test any model id" style="min-width:260px">
      <button onclick="loadEffective()">Show effective access</button>
    </div>
    <div id="eff-out" style="margin-top:14px"></div>
  </div>

  <div class="card">
    <h2>Add or update a rule</h2>
    <p class="hint">Pick a scope, then build the lists from real model ids. Saving replaces
       that scope's rule entirely.</p>
    <div class="row" style="margin-bottom:10px">
      <label class="dim" style="min-width:60px">Scope</label>${scopeSelect("ma-scope")}
    </div>
    <div class="grid2">
      <div>
        <label class="dim">Allow these models</label>
        <div class="row" style="margin:6px 0">
          <select id="ma-allow-pick"><optgroup label="Patterns">${globOpts}</optgroup>
            <optgroup label="Exact model ids">${modelOpts}</optgroup></select>
          <button class="ghost sm" onclick="addGlob('allow')">Add</button>
        </div>
        <div class="chips" id="ma-allow-list"></div>
      </div>
      <div>
        <label class="dim">Deny these models (wins over allow)</label>
        <div class="row" style="margin:6px 0">
          <select id="ma-deny-pick"><option value="">choose...</option>
            <optgroup label="Patterns">${globOpts}</optgroup>
            <optgroup label="Exact model ids">${modelOpts}</optgroup></select>
          <button class="ghost sm" onclick="addGlob('deny')">Add</button>
        </div>
        <div class="chips" id="ma-deny-list"></div>
      </div>
    </div>
    <div class="row" style="margin-top:14px">
      <button onclick="saveAccess()">Save rule</button>
      <span class="dim" id="ma-msg"></span>
    </div>
  </div>`;
  DRAFT={allow:["*"],deny:[]}; renderGlobs();
}

let DRAFT={allow:["*"],deny:[]};
function addGlob(which){
  const v=document.getElementById(`ma-${which}-pick`).value;
  if(!v)return;
  if(!DRAFT[which].includes(v))DRAFT[which].push(v);
  renderGlobs();
}
function rmGlob(which,i){DRAFT[which].splice(i,1);renderGlobs();}
function renderGlobs(){
  for(const w of ["allow","deny"]){
    const el=document.getElementById(`ma-${w}-list`);
    if(!el)continue;
    el.innerHTML=DRAFT[w].length?DRAFT[w].map((g,i)=>
      `<span class="chip ${w}">${esc(g)}
        <a href="#" onclick="rmGlob('${w}',${i});return false" class="dim"
           style="margin-left:5px;text-decoration:none">&times;</a></span>`).join(" ")
      : '<span class="dim">empty</span>';
  }
}
async function saveAccess(){
  const pk=document.getElementById("ma-scope").value;
  const msg=document.getElementById("ma-msg");
  if(!DRAFT.allow.length&&!confirm("The allow list is empty, so this scope will be denied every model. Continue?"))return;
  msg.textContent="saving...";
  if(await put(pk,"MODELS",{allow:DRAFT.allow,deny:DRAFT.deny})){
    msg.textContent="saved - enforced within ~10s"; tab("access");
  } else msg.textContent="";
}

async function loadEffective(){
  const u=document.getElementById("eff-user").value;
  const out=document.getElementById("eff-out");
  if(!u){out.innerHTML="";return;}
  out.innerHTML='<span class="dim">resolving...</span>';
  const probe=(document.getElementById("eff-probe")||{}).value||"";
  const r=await api("/effective?username="+encodeURIComponent(u)+
    (probe?"&probe="+encodeURIComponent(probe):""));
  if(r.error&&!r.models){out.innerHTML=`<div class="note bad">${esc(r.error)}</div>`;return;}
  const chain=(r.scope_chain||[]).map(s=>
    s===r.resolved_scope?`<span class="chip allow">${esc(s)} &larr; matched</span>`
                        :`<span class="chip">${esc(s)}</span>`).join(" ");
  const rows=(r.models||[]).map(m=>
    `<tr><td class="mono">${esc(m.model_id)}</td>
      <td class="${m.verdict==="allowed"?"ok":"bad"}">${esc(m.verdict)}</td>
      <td class="dim">${esc(m.reason)}</td></tr>`).join("");
  const pr=r.probe?`<div class="note ${r.probe.verdict==="allowed"?"":"bad"}">
      <b>${esc(r.probe.model_id)}</b> would be
      <b class="${r.probe.verdict==="allowed"?"ok":"bad"}">${esc(r.probe.verdict)}</b>
      for ${esc(r.username)} &mdash; ${esc(r.probe.reason)}.</div>`:"";
  out.innerHTML=`
    <div class="kpis">
      <div class="kpi"><div class="v ok">${r.allowed_count||0}</div><div class="l">models allowed</div></div>
      <div class="kpi"><div class="v bad">${r.denied_count||0}</div><div class="l">models denied</div></div>
      <div class="kpi"><div class="v">${esc((r.groups||[]).join(", ")||"none")}</div><div class="l">groups</div></div>
    </div>
    ${pr}
    <p class="hint" style="margin:10px 0 6px">Scope chain, most specific first: ${chain||"&mdash;"}</p>
    <p class="hint" style="margin:0 0 6px">Matched rule &mdash; allow:
       ${(r.allow||[]).map(g=>`<span class="chip allow">${esc(g)}</span>`).join(" ")||'<span class="dim">none</span>'}
       &nbsp; deny:
       ${(r.deny||[]).map(g=>`<span class="chip deny">${esc(g)}</span>`).join(" ")||'<span class="dim">none</span>'}</p>
    ${r.error?`<div class="note warn">${esc(r.error)}</div>`:""}
    <div class="scroll"><table>
      <thead><tr><th>Model</th><th>Verdict</th><th>Decided by</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="3" class="dim">no model ids known yet &mdash; send some traffic, or use the probe box above</td></tr>'}</tbody>
    </table></div>`;
}

/* =======================================================================
   RATE + COST
   ======================================================================= */
function viewLimits(){
  const rl=rowsOf("RATELIMIT").map(r=>`<tr>
      <td>${scopeLabel(r.pk)}</td>
      <td>${orDash(r.tokens_per_window)}</td>
      <td>${orDash(r.requests_per_window)}</td>
      <td>${orDash(r.window_seconds,"s")}</td>
      <td>${r.pooled===true?'<span class="pill ok">pooled</span>':'<span class="pill">per user</span>'}</td>
      <td style="text-align:right">${r.pk==="DEFAULT"?"":
        `<button class="danger sm" onclick="del('${esc(r.pk)}','RATELIMIT')">Delete</button>`}</td>
    </tr>`).join("");
  const bd=rowsOf("BUDGET").map(r=>`<tr>
      <td>${scopeLabel(r.pk)}</td>
      <td>$${Number(r.budget_usd||0).toFixed(4)}</td>
      <td>${orDash(r.window_seconds,"s")}</td>
      <td style="text-align:right">${r.pk==="DEFAULT"?"":
        `<button class="danger sm" onclick="del('${esc(r.pk)}','BUDGET')">Delete</button>`}</td>
    </tr>`).join("");

  document.getElementById("view").innerHTML=`
  <div class="card">
    <h2>Rate limits</h2>
    <p class="hint">
      Counts both <b>requests</b> and <b>tokens</b> in a fixed window; whichever is
      exhausted first returns <code>429 rate_limit_exceeded</code>. Resolved with the same
      first-match chain as model access
      (<code>USER#</code> &rarr; <code>GROUP#</code> &rarr; <code>DEFAULT</code>).
      <br><br>
      <b>Pooled</b> is the setting worth understanding. Off, every principal in the scope
      gets their own allowance. On, the whole scope <em>shares one</em> &mdash; the counter is
      keyed on the matched scope rather than the user, so
      <code>GROUP#ml-research</code> with 6000 tokens means the team collectively has 6000,
      not 6000 each. A gateway-native rate limit keyed on a single claim cannot express that.
      <br><br>
      Token counts include <b>generation</b>: the request side counts the prompt estimate and
      the response side corrects it once real output tokens are known.
      <br><br>
      <span class="warn">Fixed window, not sliding.</span> A burst straddling a window
      boundary can briefly exceed the intended rate. Sizing note: with real model calls
      taking ~3s, a request-count limit needs a fast burst to trip inside one window &mdash;
      the token limit trips more predictably.
    </p>
    <table><thead><tr><th>Scope</th><th>Tokens / window</th><th>Requests / window</th>
      <th>Window</th><th>Sharing</th><th></th></tr></thead>
      <tbody>${rl||'<tr><td colspan="6" class="dim">no rate limits configured</td></tr>'}</tbody></table>
    <h3>Add or update a rate limit</h3>
    <div class="row">
      ${scopeSelect("rl-scope")}
      <input id="rl-tok" type="number" min="0" placeholder="tokens / window" style="width:130px">
      <input id="rl-req" type="number" min="0" placeholder="requests / window" style="width:140px">
      <input id="rl-win" type="number" min="1" value="60" style="width:90px" title="window seconds">
      <select id="rl-pooled">
        <option value="false">per user</option>
        <option value="true">pooled across the scope</option>
      </select>
      <button onclick="saveRate()">Save</button>
      <span class="dim" id="rl-msg"></span>
    </div>
  </div>

  <div class="card">
    <h2>Cost budgets</h2>
    <p class="hint">
      A spend cap per principal per window, enforced against a DynamoDB ledger. Over budget
      returns <code>429 cost_budget_exceeded</code>.
      <br><br>
      <b>It reserves, then reconciles.</b> Output tokens do not exist before dispatch, so the
      request side charges the prompt <em>plus the caller's declared output ceiling</em>, and
      the response side replaces that reservation with the real cost. This makes the control
      pessimistic (it can block slightly early) rather than leaky &mdash; charging the prompt
      alone would let a burst of large generations overshoot before reconciliation caught up.
      Prices come from the live pricing table, refreshed daily, not from constants.
      <br><br>
      <span class="dim">Budgets are not pooled the way rate limits are: a
      <code>GROUP#</code> budget currently applies per member.</span>
    </p>
    <table><thead><tr><th>Scope</th><th>Budget</th><th>Window</th><th></th></tr></thead>
      <tbody>${bd||'<tr><td colspan="4" class="dim">no budgets configured</td></tr>'}</tbody></table>
    <h3>Add or update a budget</h3>
    <div class="row">
      ${scopeSelect("bd-scope")}
      <input id="bd-usd" type="number" step="0.0001" min="0" placeholder="budget USD" style="width:130px">
      <input id="bd-win" type="number" min="1" value="60" style="width:90px" title="window seconds">
      <button onclick="saveCost()">Save</button>
      <span class="dim" id="bd-msg"></span>
    </div>
  </div>

  <div class="card">
    <h2>Live counters</h2>
    <p class="hint">Current window state, straight from the ledger. Pooled rows are keyed on a
       group, per-user rows on a Cognito <code>sub</code> &mdash; seeing both is how you
       confirm pooling is actually in effect.</p>
    <div id="ctr-out" class="dim">loading...</div>
  </div>`;
  loadCounters();
}

async function saveRate(){
  const pk=document.getElementById("rl-scope").value;
  const msg=document.getElementById("rl-msg"); msg.textContent="saving...";
  const ok=await put(pk,"RATELIMIT",{
    tokens_per_window:Number(document.getElementById("rl-tok").value||0),
    requests_per_window:Number(document.getElementById("rl-req").value||0),
    window_seconds:Number(document.getElementById("rl-win").value||60),
    pooled:document.getElementById("rl-pooled").value==="true"});
  msg.textContent=ok?"saved - enforced within ~10s":"";
  if(ok)tab("limits");
}
async function saveCost(){
  const pk=document.getElementById("bd-scope").value;
  const msg=document.getElementById("bd-msg"); msg.textContent="saving...";
  const ok=await put(pk,"BUDGET",{
    budget_usd:Number(document.getElementById("bd-usd").value||0),
    window_seconds:Number(document.getElementById("bd-win").value||60)});
  msg.textContent=ok?"saved - enforced within ~10s":"";
  if(ok)tab("limits");
}
async function loadCounters(){
  const s=await api("/stats?minutes=60");
  const el=document.getElementById("ctr-out"); if(!el)return;
  const rc=s.rate_counters||[], sp=s.spend||[];
  el.innerHTML=`
    <table><thead><tr><th>Rate counter subject</th><th>Sharing</th><th>Tokens</th>
      <th>Requests</th></tr></thead><tbody>
      ${rc.length?rc.map(r=>`<tr><td class="mono">${esc(r.subject)}</td>
        <td>${r.pooled?'<span class="pill ok">pooled</span>':'<span class="pill">per user</span>'}</td>
        <td>${r.tokens}</td><td>${r.requests}</td></tr>`).join("")
        :'<tr><td colspan="4" class="dim">no active counters</td></tr>'}
    </tbody></table>
    <table style="margin-top:14px"><thead><tr><th>Spend: user (sub)</th><th>Window</th>
      <th>Spend</th></tr></thead><tbody>
      ${sp.length?sp.map(r=>`<tr><td class="mono">${esc(r.sub)}</td>
        <td class="mono">${esc(r.window)}</td>
        <td>$${Number(r.spend_usd).toFixed(6)}</td></tr>`).join("")
        :'<tr><td colspan="3" class="dim">no spend recorded</td></tr>'}
    </tbody></table>`;
}

/* =======================================================================
   GUARDRAILS
   ======================================================================= */
function viewGuard(){
  const rows=rowsOf("GUARDRAIL").map(r=>{
    const g=GUARDS.find(x=>x.id===r.guardrail_id);
    // A row written before the version was part of the selection has none. Say so
    // explicitly rather than printing a blank cell: the interceptor treats it as DRAFT,
    // and the admin should see that this is a fallback and not a choice.
    const ver=r.guardrail_version;
    const verCell=ver
      ? `<code>${esc(ver)}</code>`
      : `<code>DRAFT</code> <span class="dim" title="This binding predates versioned guardrail selection, so the interceptor falls back to DRAFT. Re-save it to record the version explicitly.">(implied)</span>`;
    const gone=r.guardrail_id&&!g;
    return `<tr><td>${scopeLabel(r.pk)}</td>
      <td class="mono">${orDash(r.guardrail_id)}
        ${g?`<span class="dim">${esc(g.name)}</span>`:""}
        ${gone?'<span class="warn" title="No guardrail with this id was returned by ListGuardrails. It may have been deleted, or live in another account or region. ApplyGuardrail will fail and the interceptor FAILS CLOSED, so every request in this scope would be denied.">&#9888; not found</span>':""}</td>
      <td>${verCell}</td>
      <td class="${r.enabled===true?"ok":"warn"}">${r.enabled===true?"enabled":"disabled"}</td>
      <td style="text-align:right">
        ${r.guardrail_id?`<button class="ghost sm" onclick="previewGuard('${esc(r.guardrail_id)}','${esc(ver||"DRAFT")}')">Preview</button>`:""}
        ${r.pk==="DEFAULT"?"":
          `<button class="danger sm" onclick="del('${esc(r.pk)}','GUARDRAIL')">Delete</button>`}
      </td></tr>`;
  }).join("");
  const gopts=GUARDS.map(g=>
    `<option value="${esc(g.id)}">${esc(g.name)} (${esc(g.id)})</option>`).join("");

  document.getElementById("view").innerHTML=`
  <div class="card">
    <h2>Guardrail bindings</h2>
    <p class="hint">
      Which Bedrock guardrail applies to whom. Resolved with the same first-match chain as
      the other kinds, so a <code>GROUP#</code> binding overrides <code>DEFAULT</code> and a
      <code>USER#</code> binding overrides both.
      <br><br>
      Enforced in the <b>request</b> interceptor, before dispatch: the prompt is harvested
      from the request body &mdash; including text nested inside tool results &mdash; and
      passed to <code>ApplyGuardrail</code>. A blocked request returns <code>403</code> and
      <b>never reaches a model</b>, so it costs nothing and appears in no Bedrock log.
      Because it runs pre-dispatch it applies to every upstream surface and every API shape.
      <br><br>
      Setting a scope to <b>disabled</b> exempts exactly that scope. It is a configured
      outcome, recorded as <code>allowed_guardrail_off</code> &mdash; not a failure. If
      <code>ApplyGuardrail</code> itself errors the request is <b>denied</b>, not allowed.
    </p>
    <div class="note"><b>The version is part of the binding.</b> One guardrail id serves a
      mutable <code>DRAFT</code> plus any number of published versions, and their content
      policies can differ, so choosing an id alone does not determine what gets enforced.
      Pick the version you previewed. <code>DRAFT</code> tracks edits made in the Bedrock
      console immediately; a published version is frozen, which is what you usually want
      for a policy people depend on.</div>
    <table><thead><tr><th>Scope</th><th>Guardrail</th><th>Version</th><th>State</th><th></th></tr></thead>
      <tbody>${rows||'<tr><td colspan="5" class="dim">no bindings</td></tr>'}</tbody></table>
    <h3>Add or update a binding</h3>
    <div class="row">
      ${scopeSelect("gr-scope")}
      <select id="gr-id" onchange="grVersions()"><option value="">select a guardrail...</option>${gopts}</select>
      <select id="gr-ver" title="Which version of the guardrail to enforce"><option value="DRAFT">DRAFT</option></select>
      <select id="gr-en"><option value="true">enabled</option>
        <option value="false">disabled</option></select>
      <button onclick="saveGuard()">Save</button>
      <button class="ghost" onclick="previewGuard(document.getElementById('gr-id').value,document.getElementById('gr-ver').value)">Preview selected</button>
      <span class="dim" id="gr-msg"></span>
    </div>
    ${GUARDS.length?"":'<p class="hint warn" style="margin-top:10px">No guardrails listed &mdash; either none exist in this account or the console lacks <code>bedrock:ListGuardrails</code>.</p>'}
  </div>
  <div id="gr-preview"></div>`;
}

/* Repopulate the version list for the selected guardrail.
   Fetched per guardrail rather than read from GUARDS, because the unfiltered ListGuardrails
   the list endpoint uses cannot see published versions at all — only the per-identifier call
   can. A stale or guessed list would offer a version that does not exist, and ApplyGuardrail
   failing means the interceptor fails closed on every request in that scope. */
async function grVersions(){
  const gid=document.getElementById("gr-id").value;
  const sel=document.getElementById("gr-ver");
  if(!gid){sel.innerHTML='<option value="DRAFT">DRAFT</option>';return;}
  sel.innerHTML='<option value="DRAFT">loading versions...</option>';
  let vers=["DRAFT"];
  try{
    const d=await api("/guardrails?id="+encodeURIComponent(gid));
    if(d&&d.versions&&d.versions.length)vers=d.versions;
  }catch(e){/* fall back to DRAFT, which every guardrail has */}
  sel.innerHTML=vers.map(v=>`<option value="${esc(v)}">${esc(v)}${v==="DRAFT"?" (tracks edits)":""}</option>`).join("");
}

async function saveGuard(){
  const pk=document.getElementById("gr-scope").value;
  const gid=document.getElementById("gr-id").value;
  const msg=document.getElementById("gr-msg");
  if(!gid){msg.textContent="pick a guardrail first";return;}
  msg.textContent="saving...";
  const ok=await put(pk,"GUARDRAIL",{guardrail_id:gid,
    guardrail_version:document.getElementById("gr-ver").value||"DRAFT",
    enabled:document.getElementById("gr-en").value==="true"});
  msg.textContent=ok?"saved - enforced within ~10s":"";
  if(ok)tab("guard");
}

async function previewGuard(gid,ver){
  const out=document.getElementById("gr-preview");
  if(!gid){out.innerHTML="";return;}
  out.innerHTML='<div class="card dim">loading guardrail configuration...</div>';
  // Preview the version that is actually bound. Previewing DRAFT while enforcing version 2
  // would show the admin a policy that is not the one being applied.
  const g=await api("/guardrails?id="+encodeURIComponent(gid)
                    +"&version="+encodeURIComponent(ver||"DRAFT"));
  if(g.error){out.innerHTML=`<div class="card"><div class="note bad">${esc(g.error)}</div></div>`;return;}
  const filters=(g.content_filters||[]).map(f=>
    `<tr><td>${esc(f.type)}</td><td>${orDash(f.input)}</td>
      <td>${orDash(f.output)}</td></tr>`).join("");
  const chips=a=>(a&&a.length)?a.map(x=>`<span class="chip">${esc(x)}</span>`).join(" ")
                              :'<span class="dim">none</span>';
  const vwarn=g.version_fallback
    ? `<div class="note bad"><b>&#9888; This is NOT the version you asked for.</b>
        Version <code>${esc(g.requested_version||"?")}</code> could not be read
        (<span class="mono">${esc(g.version_error||"unknown error")}</span>), so
        <code>${esc(g.version||"?")}</code> is shown instead. Do not treat the policy below
        as what would be enforced. If you bind
        <code>${esc(g.requested_version||"?")}</code> anyway,
        <code>ApplyGuardrail</code> will fail the same way and the interceptor
        <b>fails closed</b> &mdash; denying every request in that scope.</div>`
    : "";
  out.innerHTML=`<div class="card">
    <h2>Guardrail: ${esc(g.name||gid)}</h2>
    ${vwarn}
    <p class="hint">What this guardrail actually enforces. Version
       <code>${esc(g.version||"?")}</code>, status
       <code>${esc(g.status||"?")}</code>. ${esc(g.description||"")}</p>
    <h3>Content filters</h3>
    <table><thead><tr><th>Type</th><th>Input strength</th><th>Output strength</th></tr></thead>
      <tbody>${filters||'<tr><td colspan="3" class="dim">none configured</td></tr>'}</tbody></table>
    <h3>Denied topics</h3><div class="chips">${chips(g.topics)}</div>
    <h3>PII entities</h3><div class="chips">${chips(g.pii_entities)}</div>
    <h3>Other</h3>
    <p class="hint">Regex rules: ${chips(g.regexes)} &middot; managed word lists:
       ${chips(g.managed_word_lists)} &middot; custom words:
       <span class="chip">${Number(g.word_lists||0)}</span> &middot; grounding filters:
       ${chips(g.grounding_filters)}</p>
    <div class="note"><b>Note:</b> only the <b>input</b> side is enforced here. This
      deployment calls <code>ApplyGuardrail</code> in the request interceptor, so output
      strengths above are configured but not applied &mdash; response-side moderation would
      need the response interceptor to call the guardrail too.</div>
  </div>`;
}

/* =======================================================================
   STATISTICS
   ======================================================================= */
let SF={user:"",group:"",minutes:"60",q:""};
function viewStats(){
  const uo=IDS.users.map(u=>`<option value="${esc(u.username)}"${SF.user===u.username?" selected":""}>${esc(u.username)}</option>`).join("");
  const go=IDS.groups.map(g=>`<option value="${esc(g.name)}"${SF.group===g.name?" selected":""}>${esc(g.name)}</option>`).join("");
  /* Range options are CAPPED at the retention window. Offering "last 24 hours" against a
     1-hour TTL is what made this tab look broken: the range was legal, the data was gone,
     and the UI said "no requests match". RET is populated from /api/stats. */
  const capMin=Math.floor((RET.decision_ttl_seconds||86400)/60);
  const win=[["15","last 15 min"],["60","last hour"],["360","last 6 hours"],
             ["1440","last 24 hours"]]
    .filter(([v])=>Number(v)<=capMin)
    .concat([["0","everything retained ("+(RET.decision_window_label||"full window")+")"]])
    .map(([v,l])=>`<option value="${v}"${SF.minutes===v?" selected":""}>${l}</option>`).join("");
  document.getElementById("view").innerHTML=`
  <div class="card">
    <h2>Inference statistics</h2>
    <p class="hint">
      One row per request, from the interceptor's decision records &mdash; the only source
      that carries the end-user identity, the model and the true cost.
      <br><br>
      <b>Outcomes are resolved, not assumed.</b> The request interceptor runs before the Cedar
      policy engine, so its own verdict cannot know what the caller finally received: a
      request it allowed can still be refused by Cedar. The response interceptor stamps the
      real final status back onto each record, and every figure here is computed from that
      resolved outcome. Rows where the two disagree are marked <b>corrected</b> so the
      adjustment is visible rather than silent.
      <br><br>
      <b>These records are kept for ${esc(RET.decision_window_label||"a limited window")}</b>,
      then they expire. The ranges below are capped at that window for the same reason. For
      anything older &mdash; or for security review &mdash; use the governance audit log,
      linked at the bottom of this tab.
    </p>
    <div class="row" style="margin-bottom:14px">
      <select id="sf-user"><option value="">all users</option>${uo}</select>
      <select id="sf-group"><option value="">all groups</option>${go}</select>
      <select id="sf-min">${win}</select>
      <input id="sf-q" placeholder="search model, path, decision, scope..."
             value="${esc(SF.q)}" style="min-width:260px">
      <button onclick="applyStats()">Apply</button>
      <button class="ghost" onclick="SF={user:'',group:'',minutes:'60',q:''};viewStats()">Reset</button>
    </div>
    <div id="st-out" class="dim">loading...</div>
  </div>
  <div class="card">
    <h2>Gateway span diagnostics <span class="pill">opt-in</span></h2>
    <p class="hint">
      Gateway OTEL spans, fetched only on request. They are <b>not</b> a governance
      statistic: spans carry no identity and no token counts, and interceptor
      short-circuits are not spanned at all, so any denial count taken from them
      undercounts badly.
      <br><br>
      They also have almost nothing left to add. Spans distinguished two native outcomes
      &mdash; <code>errorType=throttle</code> (a native rate limit fired) and
      <code>errorType=user</code> (Cedar denied). Both native rate limits have been deleted,
      so <code>throttle</code> can no longer occur, and the Cedar case is now resolved above
      from the decision records themselves. Useful for debugging the gateway; not for
      answering who did what.
    </p>
    <button class="ghost" onclick="loadSpans()">Query spans (slow, ~10-25s)</button>
    <div id="sp-out" style="margin-top:12px"></div>
  </div>`;
  loadStats();
}
function applyStats(){
  SF={user:document.getElementById("sf-user").value,
      group:document.getElementById("sf-group").value,
      minutes:document.getElementById("sf-min").value,
      q:document.getElementById("sf-q").value};
  loadStats();
}
async function loadStats(){
  const out=document.getElementById("st-out"); out.textContent="loading...";
  const qs=new URLSearchParams();
  if(SF.user)qs.set("user",SF.user);
  if(SF.group)qs.set("group",SF.group);
  if(SF.minutes&&SF.minutes!=="0")qs.set("minutes",SF.minutes);
  if(SF.q)qs.set("q",SF.q);
  const s=await api("/stats"+(qs.toString()?"?"+qs.toString():""));
  if(s.retention){RET=s.retention;syncRange();}
  const d=s.decisions||{};
  const layer=Object.entries(d.by_denied_layer||{})
    .map(([k,v])=>`<span class="chip">${esc(k)}: ${v}</span>`).join(" ")||'<span class="dim">none</span>';
  const rows=(d.rows||[]).map(r=>{
    const denied=r.final_status>=400;
    return `<tr class="${denied?"":""}">
      <td class="mono dim">${new Date(r.ts*1000).toLocaleTimeString()}</td>
      <td>${esc(r.username)}</td>
      <td class="mono" style="font-size:11.5px">${esc(r.model)}</td>
      <td>${esc(r.effective)}${r.corrected?
        ` <span class="pill bad" title="The interceptor recorded ${esc(r.decision)}/${r.status}; the caller actually received ${r.final_status} from ${esc(r.final_layer)}.">corrected</span>`:""}</td>
      <td class="${denied?"bad":"ok"}">${r.final_status}</td>
      <td class="dim">${deniedBy(r,denied)}</td>
      <td class="dim mono">${orDash(r.scope)}</td>
      <td style="text-align:right">${r.input_tokens||"&mdash;"}</td>
      <td style="text-align:right">${r.output_tokens||"&mdash;"}</td>
      <td style="text-align:right">${r.cost_usd?("$"+r.cost_usd.toFixed(6)):"&mdash;"}</td>
    </tr>`;}).join("");
  out.innerHTML=`
    <div class="kpis">
      <div class="kpi"><div class="v">${d.total||0}</div><div class="l">requests shown</div></div>
      <div class="kpi"><div class="v ok">${d.allowed||0}</div><div class="l">allowed</div></div>
      <div class="kpi"><div class="v bad">${d.denied||0}</div><div class="l">denied</div></div>
      <div class="kpi"><div class="v ${d.corrected?"warn":""}">${d.corrected||0}</div><div class="l">outcome corrected</div></div>
      <div class="kpi"><div class="v">$${Number(d.cost_usd||0).toFixed(4)}</div><div class="l">true cost</div></div>
      <div class="kpi"><div class="v">${d.output_share_pct||0}%</div><div class="l">output share</div></div>
      <div class="kpi"><div class="v">${d.input_tokens||0}</div><div class="l">input tokens</div></div>
      <div class="kpi"><div class="v">${d.output_tokens||0}</div><div class="l">output tokens</div></div>
    </div>
    <p class="hint" style="margin:12px 0 6px">Denials by layer: ${layer}
      ${d.total_unfiltered&&d.total!==d.total_unfiltered?
        `<span class="dim"> &middot; ${d.total} of ${d.total_unfiltered} retained records match the filter</span>`:""}
      ${d.corrected?`<br><span class="warn">${d.corrected} row(s) were recorded as allowed by the interceptor but refused later &mdash; counted as denials here.</span>`:""}
    </p>
    <div class="scroll"><table>
      <thead><tr><th>Time</th><th>User</th><th>Model</th><th>Outcome</th><th>Status</th>
        <th title="Which enforcement layer refused the request. Blank for anything that was not refused.">Denied by</th>
        <th>Scope</th><th style="text-align:right">In</th>
        <th style="text-align:right">Out</th><th style="text-align:right">Cost</th></tr></thead>
      <tbody>${rows||`<tr><td colspan="10" class="dim">${emptyMsg(d)}</td></tr>`}</tbody>
    </table></div>
    ${archiveNote(s.retention,d)}`;
}

/* The range select is built before the first /api/stats response, so it starts from the
   defaults in RET. Once the real retention arrives, re-cap the options — otherwise a
   deployment configured with a shorter TTL would keep offering a range it cannot answer,
   which is the exact defect this is here to prevent. Preserves the current selection. */
function syncRange(){
  const sel=document.getElementById("sf-min");
  if(!sel)return;
  const capMin=Math.floor((RET.decision_ttl_seconds||86400)/60);
  const opts=[["15","last 15 min"],["60","last hour"],["360","last 6 hours"],
              ["1440","last 24 hours"]]
    .filter(([v])=>Number(v)<=capMin)
    .concat([["0","everything retained ("+(RET.decision_window_label||"full window")+")"]]);
  const want=opts.some(([v])=>v===SF.minutes)?SF.minutes:"0";
  const next=opts.map(([v,l])=>
    `<option value="${esc(v)}"${want===v?" selected":""}>${esc(l)}</option>`).join("");
  if(sel.innerHTML!==next){
    sel.innerHTML=next;
    if(want!==SF.minutes)SF.minutes=want;
  }
}

/* `final_layer` attributes a DENIAL and nothing else — for anything dispatched it is the
   sentinel "none". The column was headed "Decided by", which promised more than the data
   carries: every allowed row rendered as a bare dash, and since most rows are allowed the
   column looked broken rather than empty-by-design.
   So the header is "Denied by" and the dash now carries a tooltip saying why it is blank.
   Nothing is lost: what allowed a request is already in Outcome, and the rule that decided
   it is in Scope. */
function deniedBy(r,denied){
  if(denied&&r.final_layer&&r.final_layer!=="none")return esc(r.final_layer);
  if(denied)return '<span title="Denied, but no layer could be attributed. Expected only if the decision record predates outcome resolution.">unattributed</span>';
  return '<span title="Nothing denied this request. It passed the interceptor controls and the policy engine. This column attributes denials only — see Outcome for what happened and Scope for the rule that applied.">&mdash;</span>';
}

/* An empty table has two very different causes and they must not read alike:
     - filters excluded everything that IS retained
     - nothing is retained, because the records aged out
   Reporting the second as "no requests match" is what made a healthy console look broken. */
function emptyMsg(d){
  if(d.total_unfiltered)
    return "No retained request matches these filters &mdash; "
          +`${d.total_unfiltered} record(s) are retained. Try widening the range or clearing the search.`;
  return "No requests recorded in the retained window. "
        +"Either nothing has been sent through the gateway recently, or the records have aged out "
        +"&mdash; see below for the durable copy.";
}

/* The hand-off to the archive. Always shown, and stated as a property of the design
   rather than only surfacing when something looks wrong. */
function archiveNote(ret,d){
  if(!ret)return "";
  const win=esc(ret.decision_window_label||"the retention window");
  const days=Number(ret.audit_retention_days||0);
  const keep=days?`${days} days`:"indefinitely";
  const link=ret.audit_insights_url
    ? `<a href="${esc(ret.audit_insights_url)}" target="_blank" rel="noopener noreferrer">Open the audit log in CloudWatch Logs Insights</a>`
    : "";
  const grp=ret.audit_log_group
    ? ` <code>${esc(ret.audit_log_group)}</code>` : "";
  return `<div class="note" style="margin-top:14px">
    <b>Where this data comes from, and how far back it goes.</b>
    This tab reads the interceptor's <code>DECISION#</code> records in DynamoDB, which are
    kept for <b>${win}</b>. They are the operational copy: cheap to query, and enough to run
    the governance plane day to day. They are <b>not</b> the system of record, and they
    expire &mdash; so an empty table after an idle period is the TTL working, not a fault.
    <br><br>
    The <b>system of record is the governance audit log</b>${grp}, retained
    <b>${esc(keep)}</b>. Both interceptors write one structured record per request stage
    there, joined on <code>request_id</code>, and it is the copy to use for anything older
    than ${win}, for security review, or for evidence. ${link}
    <br><br>
    <span class="dim">One request writes <b>two</b> audit records &mdash; a REQUEST stage
    carrying the identity and the interceptor's decision, and a RESPONSE stage carrying the
    resolved outcome and true cost &mdash; joined on <code>request_id</code>. The link above
    opens the REQUEST stage; switch the filter to <code>stage = 'RESPONSE'</code> for
    <code>final_status</code> and <code>final_layer</code>.</span>
    <br><br>
    <span class="dim">Reading this tab directly from the audit log &mdash; so the range is
    limited by the archive rather than by the DynamoDB TTL &mdash; is tracked as remaining
    work. Until then the two sources are queried in two places, deliberately: this one is
    fast, that one is complete.</span>
  </div>`;
}
async function loadSpans(){
  const out=document.getElementById("sp-out");
  out.innerHTML='<span class="dim">querying CloudWatch Logs Insights...</span>';
  const e=await api("/diagnostics/spans?minutes=60");
  if(e.error){out.innerHTML=`<div class="note bad">${esc(e.error)}</div>`;return;}
  const kv=o=>Object.entries(o||{}).map(([k,v])=>
    `<span class="chip">${esc(k)}: ${v}</span>`).join(" ")||'<span class="dim">none</span>';
  out.innerHTML=`<p class="hint">${e.total||0} spans in the last hour.</p>
    <p class="hint">By status: ${kv(e.by_status)}<br>By layer: ${kv(e.by_layer)}</p>`;
}

if(TOKEN)boot();
</script>
</body></html>
"""
