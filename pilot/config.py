"""Central configuration for the AgentCore Gateway inference-governance pilot.

All environment- and identity-specific values live here so the stack code stays
declarative. Nothing secret is stored here: the Cognito app client has no secret,
and demo passwords are supplied via env var or randomly generated per synth (never
hardcoded) — see `_demo_password` below.
"""
import os
import secrets
import string
from dataclasses import dataclass, field


def _demo_password(env_var: str) -> str:
    """Resolve a demo user's password, without shipping a functional literal.

    Precedence: the given env var, else a random per-synth password that satisfies
    Cognito's default policy (upper/lower/digit/symbol). Nothing usable is hardcoded,
    so the repo contains no real credential. When you let it auto-generate, read the
    value back from the CloudFormation output / `pilot/config.py` at deploy time, or
    set the env var yourself for a known value.
    """
    supplied = os.environ.get(env_var)
    if supplied:
        return supplied
    alphabet = string.ascii_letters + string.digits
    return (
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + "!"
        + "".join(secrets.choice(alphabet) for _ in range(12))
    )


# ---- AWS environment -------------------------------------------------------
# Resolved from the ambient environment so this repo deploys into ANY account
# without editing code. Resolution order:
#   1. ACGW_ACCOUNT / ACGW_REGION        — explicit override
#   2. CDK_DEFAULT_ACCOUNT / CDK_DEFAULT_REGION — set by the CDK CLI from your creds
#   3. STS / boto3 session               — so a bare `python app.py` also works
# The account/region are needed at SYNTH time (IAM resource ARNs and the Cognito
# discovery URL are built as real strings, not CFN tokens), which is why this is
# resolved eagerly rather than left as an environment-agnostic stack.
def _resolve_env() -> tuple[str, str]:
    account = os.environ.get("ACGW_ACCOUNT") or os.environ.get("CDK_DEFAULT_ACCOUNT")
    region = os.environ.get("ACGW_REGION") or os.environ.get("CDK_DEFAULT_REGION")
    if account and region:
        return account, region

    try:
        import boto3

        session = boto3.session.Session()
        region = region or session.region_name
        if not account:
            account = session.client("sts").get_caller_identity()["Account"]
    except Exception as exc:  # noqa: BLE001 - we re-raise with actionable guidance
        raise RuntimeError(
            "Could not determine the target AWS account/region. Configure AWS "
            "credentials (aws configure / SSO login), or set ACGW_ACCOUNT and "
            f"ACGW_REGION explicitly. Underlying error: {exc}"
        ) from exc

    if not account or not region:
        raise RuntimeError(
            "Could not determine the target AWS account/region. Set ACGW_ACCOUNT "
            "and ACGW_REGION, or configure a default region for your AWS profile."
        )
    return account, region


AWS_ACCOUNT, AWS_REGION = _resolve_env()

# Resource naming: every resource this pilot creates carries this prefix so it
# is visually isolated from the other gateways already in the account
# (ameren-kb-gateway-*, TestGateway*). Do not reuse these names elsewhere.
PREFIX = "acgw-pilot"
STACK_NAME = "AcgwPilotFoundationStack"


# ---- Cognito (default identity provider for the published pilot) -----------
# Cognito is provisioned by CDK so the whole pilot is self-contained (no external
# tenant). Path A auth model: browser-free USER_PASSWORD_AUTH login; the gateway
# authorizer validates issuer (via discovery URL) + audience (the app client id);
# per-user/per-group authorization is enforced by Cedar keyed on `cognito:groups`.
# NOTE: InitiateAuth access tokens do NOT carry custom resource-server scopes, so
# we do not use allowed_scopes — group-based Cedar is the authorization layer.
# v3: DELETING the `custom:tier` attribute forced a NEW pool. Verified the hard way —
# removing it from the schema and deploying fails with:
#
#     Invalid request provided: Existing schema attributes cannot be modified or deleted.
#
# Renaming the pool does not help either, because `UserPoolName` updates in place rather
# than replacing the resource. The only route is a replacement pool, which is why the
# CDK construct id is `Cognito3` (v2 existed for the same reason when tier was ADDED).
#
# The lesson worth carrying: **Cognito custom attributes are permanent.** Add one only
# when a value genuinely must live on the user record. `tier` did not — it belonged in a
# policy table all along, which is exactly where it ended up.
COGNITO_POOL_NAME = f"{PREFIX}-pool-v3"
COGNITO_CLIENT_NAME = f"{PREFIX}-client-v3"

# ---- ONE IDENTITY AXIS: GROUP MEMBERSHIP -----------------------------------
# `tier` HAS BEEN DELETED. It only ever existed because a native gateway rate limit
# needs a SCALAR claim to key on and `cognito:groups` is multi-valued — so a
# single-value `tier` claim was invented, plus a pre-token-generation Lambda to inject
# it and the ESSENTIALS feature plan to allow access-token customization. That native
# tier/model limit has since been deleted for contradicting the config table, and rate
# limiting has moved into the interceptor, so tier had no remaining purpose. Removing
# it also removed the trigger Lambda and the ESSENTIALS requirement.
#
# There is now ONE identity axis — group membership — and the governance config table
# maps scope -> policy. Two different questions, two different mechanisms, same axis:
#   * "may you use inference at all?"      Cedar, on `cognito:groups`
#   * "which models / how fast / how much" config table, on GROUP# and USER# scopes
COGNITO_GROUP_PLATFORM = "ai-platform"     # Cedar gate: may use the gateway at all
COGNITO_GROUP_RESEARCH = "ml-research"     # entitlement group: cleared for premium models

# Groups the stack creates:
#   group name -> (group construct id, membership-id suffix, description)
#
# Both ids are PINNED rather than derived from the group name. CloudFormation identifies
# resources by logical id, so renaming one is a delete-and-create — and because CFN
# creates before it deletes, it fails with "UserPoolGroup ... already exists". The
# original stack's ids (`PlatformGroup`, `<User>InPlatform`) are therefore kept verbatim,
# and only the new group introduces new ids.
COGNITO_GROUPS = {
    COGNITO_GROUP_PLATFORM: ("PlatformGroup", "InPlatform",
                             "Members may use the gateway's inference (Cedar-gated)."),
    COGNITO_GROUP_RESEARCH: ("ResearchGroup", "InResearch",
                             "Cleared for premium models, with a POOLED rate allowance."),
}

# Sample users. Group membership is now the ONLY identity input to governance.
#   alice — ai-platform + ml-research -> allowed in; research policy clears premium
#   bob   — ai-platform               -> allowed in; default policy denies premium
#   carol — no groups                 -> denied entry entirely by Cedar
COGNITO_USERS = {
    "alice": {"groups": [COGNITO_GROUP_PLATFORM, COGNITO_GROUP_RESEARCH],
              "email": "alice@example.com"},
    "bob":   {"groups": [COGNITO_GROUP_PLATFORM], "email": "bob@example.com"},
    "carol": {"groups": [], "email": "carol@example.com"},
}
# Demo-only password for the sample inference users. NOT hardcoded: set ACGW_DEMO_PASSWORD
# for a known value, otherwise a random per-synth password is generated. The accounts exist
# only in the throwaway pool this stack creates. See docs/DEPLOYMENT.md for how to retrieve
# or set it.
COGNITO_DEMO_PASSWORD = _demo_password("ACGW_DEMO_PASSWORD")

# ---- Admin identity (for the governance console) ---------------------------
# Deliberately SEPARATE from the inference users above: an administrator who can
# widen model access and raise spend caps should be a distinct, attributable
# identity, and should not automatically have inference access itself.
COGNITO_ADMIN_GROUP = "gateway-admins"
COGNITO_ADMIN_USER = "gwadmin"
# Demo-only admin password; same mechanism as COGNITO_DEMO_PASSWORD above. NOT hardcoded:
# set ACGW_ADMIN_PASSWORD for a known value, otherwise a random per-synth password is used.
COGNITO_ADMIN_PASSWORD = _demo_password("ACGW_ADMIN_PASSWORD")


def cognito_issuer(region: str, user_pool_id: str) -> str:
    return f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"


def cognito_discovery_url(region: str, user_pool_id: str) -> str:
    return f"{cognito_issuer(region, user_pool_id)}/.well-known/openid-configuration"


# NOTE: an earlier iteration used Microsoft Entra ID as the identity provider. It
# worked end to end, but was replaced by Cognito so this pilot is self-contained
# (no external tenant) and can log in without a browser. Those findings — the
# requestedAccessTokenVersion:2 issuer mismatch, the bare-client-id `aud`, the
# GUID group claims and the groups-overage caveat — are preserved in
# docs/APPENDIX-entra.md. No Entra configuration remains in code.


# ---- Models ----------------------------------------------------------------
@dataclass(frozen=True)
class ModelConfig:
    # Inference connector for Bedrock. Valid connector IDs are ONLY:
    # bedrock-mantle, openai, anthropic (verified against control-API reference).
    # There is no `bedrock-runtime` connector — `bedrock-mantle` IS the Bedrock one.
    connector_id: str = "bedrock-mantle"
    # Model ID as exposed by the connector via GET /inference/v1/models.
    # Format is bedrock/<provider>.<model>. Anthropic models are served ONLY
    # at /inference/v1/messages and require "anthropic_version" in the body.
    # DEFAULT SERVING PATH = the explicit PROVIDER target (`bedrockprov`), not the
    # connector. The provider configuration is the more robust option: it states the
    # endpoint, operations, path rewriting and model mappings explicitly instead of
    # relying on built-in defaults, which is what you want when the same governance
    # plane has to span several upstream surfaces. The connector target (`bedrock`)
    # stays deployed as a comparison artifact — governance was verified identical
    # through both.
    inference_model_id: str = "bedrockprov/anthropic.claude-sonnet-5"
    anthropic_version: str = "bedrock-2023-05-31"
    # The "premium" model denied by the DEFAULT config scope and re-allowed for the
    # ml-research GROUP. Enforced in the interceptor, so uniform across both surfaces.
    premium_model_id: str = "bedrockprov/anthropic.claude-opus-5"  # what the CLIENT sends
    # The connector-translated routing id used by the rate-limit qualifiedModelId
    # dimension (verified empirically; NOT the same as the client-sent string).
    premium_qualified_model_id: str = "anthropic.claude-opus-5"

    # ---- Provider target (guardrail experiment) ----------------------------
    # A SECOND inference target built as an explicit PROVIDER (not a connector),
    # aimed at the Bedrock mantle endpoint. The connector declares no input
    # schema, so context.input.prompt/.body are "not present" for guardrails.
    # The provider declares operations/paths/models explicitly — this target
    # tests whether that surfaces request content to the guardrail policy.
    # (Docs Bedrock provider example: endpoint below, providerPrefix.strip on ".")
    provider_target_name: str = "bedrockprov"
    provider_endpoint: str = field(
        default_factory=lambda: f"https://bedrock-mantle.{AWS_REGION}.api.aws"
    )
    provider_prefix_separator: str = "."
    # Model glob the provider operation routes (Anthropic messages family).
    provider_model_glob: str = "anthropic.claude-*"
    # Anthropic Messages op: gateway path -> upstream provider path.
    provider_op_path: str = "/v1/messages"
    provider_op_provider_path: str = "/anthropic/v1/messages"

    # ---- SECOND UPSTREAM SURFACE: bedrock-runtime (provider target) --------
    # The governance plane must hold over BOTH serverless surfaces. There is no
    # `bedrock-runtime` connector (valid connector IDs are only bedrock-mantle /
    # openai / anthropic), so runtime can only be fronted with an explicit
    # PROVIDER configuration.
    #
    # Why this works (verified directly against bedrock-runtime):
    #   * InvokeModel accepts the Anthropic Messages body VERBATIM
    #     ({anthropic_version, max_tokens, messages}) and returns the same shape
    #     the gateway's /v1/messages contract already uses -> no body translation.
    #   * It also TOLERATES the extra top-level `model` field the gateway forwards
    #     from the client (runtime takes the model from the PATH, not the body).
    # The catch: runtime embeds the model id in the path and `providerPath` is a
    # STATIC string with no templating, so each model needs its OWN operation
    # entry pinning that model to its own /model/<id>/invoke path.
    runtime_target_name: str = "bedrockrt"
    runtime_endpoint: str = field(
        default_factory=lambda: f"https://bedrock-runtime.{AWS_REGION}.amazonaws.com"
    )
    runtime_op_path: str = "/v1/messages"
    # Runtime uses cross-region inference-profile ids (us.*), which differ from
    # mantle's ids — this matters for the rate-limit qualifiedModelId dimension.
    runtime_base_model: str = "us.anthropic.claude-sonnet-5"
    runtime_premium_model: str = "us.anthropic.claude-opus-5"

    def runtime_provider_path(self, model_id: str) -> str:
        """bedrock-runtime InvokeModel path for a specific model."""
        return f"/model/{model_id}/invoke"


MODELS = ModelConfig()


# ---- INTERCEPTOR-ENFORCED RATE LIMITS (the ONLY rate mechanism) -------------
# There is no native gateway rate limit in this stack any more. Both were deleted:
# the tier/model `rate:0` limit because it contradicted the config table, and the
# per-user TPM limit on `jwt.sub` because it covered only half the traffic.
#
# Native limits attach only on RECOGNISED INFERENCE PATHS, so the bedrock-runtime
# passthrough target was never metered. Keeping one as "defense-in-depth" meant one
# surface had a backstop and the other did not — and with the Bedrock surfaces
# converging on the runtime endpoint, a mantle-only control is a dead end.
#
# Enforcing here also buys three things native limits cannot express:
#   * BOTH SURFACES, because the interceptor runs pre-dispatch on every path
#   * POOLED limits — a GROUP# limit is shared across the group, not granted per member
#   * OUTPUT tokens counted, because the RESPONSE interceptor reconciles actual usage
# Sized like DEMO_COST_BUDGET_USD: deliberately small so a short burst in the notebook
# trips a 429 without waiting. Raise substantially for anything real.
DEMO_RATE_TOKENS_PER_WINDOW = 2000   # tokens (input + reconciled output) per window
DEMO_RATE_REQUESTS_PER_WINDOW = 10   # requests per window
DEMO_RATE_WINDOW_SECONDS = 60

# ---- Cross-surface COST governance (interceptor + DynamoDB ledger) ---------
# Native token rate limits cannot do this: they meter INPUT tokens only (so they
# never bound generation spend) and they do not apply to the bedrock-runtime
# passthrough path at all. The interceptor accumulates estimated cost in a ledger,
# which works identically on BOTH surfaces.
#
# Deliberately tiny so the walkthrough can trip the budget in a couple of calls.
# Sized for RESERVATION-based enforcement: a 400-token generation on sonnet reserves
# ~0.006 (400/1000 x 0.015), so ~3 such calls fit before the budget blocks.
# ---- FAIL-CLOSED INTERCEPTOR TIMING ----------------------------------------
# MEASURED, and the reason these two settings exist (see docs/FINDINGS.md):
#
#   interceptor throttled -> gateway 400  FAIL CLOSED
#   interceptor raises    -> gateway 400  FAIL CLOSED
#   interceptor TIMES OUT -> gateway 200  FAIL *OPEN*, model invoked ungoverned
#
# There is no gateway setting to change the third row, so the interceptor must never
# reach its Lambda timeout. It enforces its own budget instead and returns an explicit
# 403 while it still has time to speak.
#
# TIMEOUT is therefore HEADROOM, sized above the worst honest path (config scan + rate
# counter + ledger write + ApplyGuardrail, each with its own connect/read timeout).
# SAFETY_MARGIN is what the interceptor keeps in reserve to emit its verdict and audit
# record. Raising the margin makes the control deny earlier under load — the correct
# bias for a fail-closed design, and the knob to turn if `governance_timeout` denials
# ever appear in the audit log.
INTERCEPTOR_TIMEOUT_SECONDS = 20
INTERCEPTOR_SAFETY_MARGIN_MS = 2000

DEMO_COST_BUDGET_USD = 0.02       # per user, per window
DEMO_COST_WINDOW_SECONDS = 60     # fixed window

# ---- How long the admin console can look back -------------------------------
# The interceptor writes one `DECISION#` record per request into the ledger table, and
# the admin console's Statistics tab is computed ENTIRELY from those records. So this
# TTL is not an implementation detail: it IS the console's history horizon.
#
# It was 1 hour, which was shorter than the ranges the UI offered. The result looked
# exactly like a broken console — an admin selecting "last 24 hours" after an idle night
# got an empty table, because the rows had been reaped rather than filtered out. Whatever
# this value is, the UI's longest range must not exceed it.
#
# 24 hours is a deliberate trade, not a maximum:
#   * storage — 24x more retained rows than the old 1-hour window. Small per row, and the
#     table is PAY_PER_REQUEST, so this is cents at demo volume.
#   * scan cost — the console reads decisions with a FULL TABLE SCAN, so its per-page-load
#     cost now grows with a day of traffic rather than an hour. That is the real limit
#     here, and it is why this is not simply set to the audit log's 90 days: past a certain
#     volume the answer is to read the audit log (indexed, 90-day) instead of scanning
#     DynamoDB. Tracked as remaining work.
#
# The audit log remains the source of truth and the archive. These records are the
# operational copy the console can query cheaply.
DECISION_RECORD_TTL_SECONDS = 86400   # 24 hours; must be >= the UI's longest range
# NOTE on layering: rate limit and cost budget both live in the interceptor and answer
# different questions (request/token volume vs spend). The rate limit is evaluated
# first, so a burst trips 429 rate_limit_exceeded before 429 cost_budget_exceeded.
# Size them so whichever one you mean to demonstrate is the one that fires.

# Approximate input price per 1K tokens, matched by model-id SUBSTRING so a single
# entry covers the same model on both surfaces (mantle `anthropic.claude-opus-5`
# and runtime `us.anthropic.claude-opus-5`). Illustrative values for the demo —
# replace with current Bedrock pricing for real use.
MODEL_INPUT_PRICES_PER_1K = {
    "claude-opus": 0.015,
    "claude-sonnet": 0.003,
    "claude-haiku": 0.0008,
}
DEFAULT_INPUT_PRICE_PER_1K = 0.003

# OUTPUT tokens are priced substantially higher than input (typically ~5x) and usually
# dominate real spend — which is exactly why a prompt-only ledger understates cost, and
# why output-token accounting needs a RESPONSE interceptor.
MODEL_OUTPUT_PRICES_PER_1K = {
    "claude-opus": 0.075,
    "claude-sonnet": 0.015,
    "claude-haiku": 0.004,
}
DEFAULT_OUTPUT_PRICE_PER_1K = 0.015

# ---- Output-token accounting (RESPONSE interceptor) ------------------------
# TRADE-OFF: response interception on HTTP/inference targets is BUFFERED, so enabling
# this costs token-by-token streaming. Set False to restore streaming and fall back to
# prompt-only cost accounting.
ENABLE_OUTPUT_TOKEN_ACCOUNTING = True
# Verbose structural logging in the response interceptor. It was used to establish what
# the response payload actually contains (notably: `gatewayRequest` is None, so there is
# NO JWT — attribution has to come from the REQUEST_ID in Lambda client context). That
# question is settled, so it is off by default; flip it on to re-inspect the payload.
USAGE_PROBE_MODE = False

# ---- MODEL PRICING (refreshed from the AWS Price List API) -----------------
# Cost enforcement built on hardcoded rates is wrong the moment AWS changes one, and
# the values below were measurably wrong: verified against the live Price List API,
# claude-opus-5 was being priced at 0.015/0.075 when the real rates are 0.005/0.025 —
# a 3x over-charge. So prices come from a table, refreshed on a schedule.
PRICING_TABLE_NAME = f"{PREFIX}-model-pricing"
# "global" for cross-region inference profiles (us.*), "regional" for bare model ids.
# The two scopes differ by roughly 10%. Runtime here uses us.* profiles.
PRICING_RATE_SCOPE = "global"
PRICING_REFRESH_HOUR_UTC = 3          # daily EventBridge schedule
PRICING_CACHE_TTL_SECONDS = 300       # per-container cache in the interceptors
# If the table has not refreshed in this long, treat prices as stale and say so on the
# audit record. Enforcement continues on the last known rates rather than failing open
# to "free", which would be the worse error.
PRICING_STALE_AFTER_SECONDS = 60 * 60 * 36

# ---- Central governance AUDIT LOG ------------------------------------------
# ONE searchable place for request/response detail and guardrail interventions,
# independent of whatever Bedrock invocation logging is (or is not) enabled at the
# account level. Both interceptor Lambdas are pointed at this SAME log group via the
# Lambda `logGroup` property, so a security reviewer has a single destination rather
# than one log group per function plus a short-TTL DynamoDB table.
#
# Why not Bedrock invocation logging: it is an account-level setting this stack does
# not own, mantle does not offer it, and it records the Bedrock call — not the
# governance decision. A guardrail denial never reaches Bedrock at all, so it would
# be invisible. Gateway spans are worse: no identity, no token counts, and
# interceptor short-circuits are not spanned at all.
AUDIT_LOG_GROUP_NAME = f"/{PREFIX}/governance-audit"
# A CloudWatch `RetentionDays` member name — e.g. ONE_MONTH, THREE_MONTHS, ONE_YEAR,
# SEVEN_YEARS, INFINITE. Deliberately much longer than the decision records'
# `DECISION_RECORD_TTL_SECONDS`: those are operational state for the console, this is
# the archive a security reviewer searches.
AUDIT_LOG_RETENTION = "THREE_MONTHS"

# The same retention as a NUMBER OF DAYS, for display in the admin console.
#
# This is not derivable from the CDK enum: `logs.RetentionDays.THREE_MONTHS.value` is the
# string "THREE_MONTHS" under the Python jsii binding, not 90. Rather than parse a member
# name at runtime inside a Lambda, the day count is mapped explicitly here — the console
# only needs it to tell an operator how far back the archive goes.
_RETENTION_DAYS = {
    "ONE_DAY": 1, "THREE_DAYS": 3, "FIVE_DAYS": 5, "ONE_WEEK": 7, "TWO_WEEKS": 14,
    "ONE_MONTH": 30, "TWO_MONTHS": 60, "THREE_MONTHS": 90, "FOUR_MONTHS": 120,
    "FIVE_MONTHS": 150, "SIX_MONTHS": 180, "ONE_YEAR": 365, "THIRTEEN_MONTHS": 400,
    "EIGHTEEN_MONTHS": 545, "TWO_YEARS": 731, "FIVE_YEARS": 1827, "TEN_YEARS": 3653,
    "INFINITE": 0,
}


def audit_log_retention_days() -> int:
    """Day count for `AUDIT_LOG_RETENTION`; 0 means never expires. Unknown -> 0."""
    return _RETENTION_DAYS.get(AUDIT_LOG_RETENTION, 0)

# Prompt text is DELIBERATELY NOT logged by default. Prompts routinely contain the
# most sensitive data in the system, and an audit log is exactly the wrong place to
# concentrate it. What is always recorded is a SHA-256 of the prompt plus its length,
# which is enough to correlate, deduplicate and prove tampering without retaining the
# content. Set this True only if you accept prompt content in CloudWatch Logs.
AUDIT_LOG_PROMPT_TEXT = False
# When prompt logging IS enabled, truncate to this many characters per text unit.
AUDIT_LOG_PROMPT_MAX_CHARS = 2000

# RESPONSE text, same posture as prompts and for a sharper reason: a response is where
# the model's *generated* content lands, so it can contain PII the model produced or
# repeated back. A SHA-256 and a length are always recorded; the text only on request.
AUDIT_LOG_RESPONSE_TEXT = False
AUDIT_LOG_RESPONSE_MAX_CHARS = 2000

# Tool NAMES are always recorded — "who gave the model a shell?" is a governance
# question and a name is not sensitive. Tool SCHEMAS are opt-in because input schemas
# often embed internal field names, endpoints and example values.
AUDIT_LOG_TOOL_SCHEMAS = False

# ---- Data protection on the audit log --------------------------------------
# CloudWatch Logs can mask sensitive data AT INGEST, which is what makes opting into
# prompt/response logging defensible rather than reckless: the operator sees
# `***MASKED***` unless they hold the separate `logs:Unmask` permission.
#
# This is deliberately ON even though content logging is OFF, because a prompt hash is
# not the only way content leaks — a guardrail assessment, an error message or a tool
# argument can carry an identifier too.
AUDIT_DATA_PROTECTION_ENABLED = True
# Managed data identifiers to mask. Names must match `aws_logs.DataIdentifier` members.
# Kept to a focused set: every added identifier costs scanning money per GB ingested.
AUDIT_DATA_PROTECTION_IDENTIFIERS = [
    "EMAILADDRESS",
    "CREDITCARDNUMBER",
    "SSN_US",
    "PHONENUMBER_US",
    "AWSSECRETKEY",
    "IPADDRESS",
    "ADDRESS",
    "NAME",
]

# ---- Governance config layer -----------------------------------------------
# Policy data (model access, budgets, guardrail selection) lives in DynamoDB so an
# administrator can change it at runtime instead of redeploying. The interceptor
# caches lookups for this long, which is therefore the worst-case delay between an
# admin change and it taking effect. Small enough to demo, large enough to keep the
# per-request read cost near zero.
CONFIG_CACHE_TTL_SECONDS = 10

