"""AgentCore Gateway REQUEST interceptor: guardrail enforcement over inference.

WHY THIS EXISTS
---------------
Native guardrail-in-policy (`when guardrails { BedrockGuardrails::PromptAttack(...) }`)
can SEE a provider target's request body (context.input.messages resolves), but the
guardrail data-path argument must be a scalar STRING and the Anthropic Messages body
has no flat prompt field — the text is nested in `messages[].content[].text`
(typed Set<record>), unreachable by a scalar dot-path. See findings.md.

This request interceptor closes that gap: it receives the RAW request body (base64),
decodes + flattens the prompt text itself (trivial in Python), and calls the Bedrock
`ApplyGuardrail` API directly. If the guardrail intervenes (e.g. PROMPT_INJECTION /
a blocked content filter), the interceptor SHORT-CIRCUITS by returning a
`transformedGatewayResponse` (HTTP 403) — the gateway returns it immediately and
never calls Bedrock. This is the documented request-interceptor block mechanism.

PAYLOAD CONTRACT (HTTP/inference target — the `http` shape, NOT `mcp`)
---------------------------------------------------------------------
Input:  { "interceptorInputVersion": "1.0",
          "http": { "gatewayRequest": { "path", "httpMethod", "headers"?, "body": <base64> } } }
Output (pass):   { "interceptorOutputVersion": "1.0", "http": {} }
Output (block):  { "interceptorOutputVersion": "1.0",
                   "http": { "transformedGatewayResponse": {
                       "statusCode": 403, "contentType": "application/json",
                       "headers": {...}, "body": <base64 json> } } }

Inference targets share the HTTP interceptor payload; bodies are base64 strings.
Response streaming is NOT intercepted for HTTP/inference targets (buffered-only) —
so we enforce on the REQUEST (prompt-injection / input content), which is exactly
where prompt-attack guardrails belong.
"""
import base64
import fnmatch
import hashlib
import json
import os
import re
import time

import boto3
from botocore.config import Config as BotoConfig

_REGION = os.environ.get("AWS_REGION", "us-east-1")
_GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
_GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

# --- central governance audit log -------------------------------------------
# This function's CloudWatch log group IS the shared audit log group (set via the
# Lambda `logGroup` property), and the RESPONSE interceptor points at the same one.
# So a plain structured print lands in the single destination a security reviewer
# searches — no PutLogEvents plumbing, no per-stream throttling, no second copy to
# keep consistent. Records are one-line JSON tagged `audit=true` so Logs Insights
# can separate them from operational logging.
_AUDIT_SCHEMA = "acgw.governance.audit/1"
_AUDIT_PROMPTS = os.environ.get("AUDIT_LOG_PROMPT_TEXT", "false").lower() == "true"
_AUDIT_PROMPT_MAX = int(os.environ.get("AUDIT_LOG_PROMPT_MAX_CHARS", "2000") or 2000)
# Tool NAMES are always recorded; SCHEMAS are opt-in.
_AUDIT_TOOL_SCHEMAS = os.environ.get("AUDIT_LOG_TOOL_SCHEMAS", "false").lower() == "true"

# --- interceptor-enforced rate limits (the ONLY rate mechanism) -------------
# There are NO native gateway rate limits in this stack. They attach only on recognised
# inference paths, so the bedrock-runtime passthrough target was never metered by them,
# and they meter input tokens only so they cannot bound generation. Enforcing here also
# allows POOLED group allowances, which a native limit keyed on a scalar claim cannot
# express. See docs/FINDINGS.md.
_RATE_TOKENS = int(os.environ.get("RATE_TOKENS_PER_WINDOW", "0") or 0)
_RATE_REQUESTS = int(os.environ.get("RATE_REQUESTS_PER_WINDOW", "0") or 0)
_RATE_WINDOW = int(os.environ.get("RATE_WINDOW_SECONDS", "60") or 60)
# Comma-separated substrings identifying premium-only models, matched against the
# resolved model id from EITHER surface (e.g. "anthropic.claude-opus-5" on mantle,
# "us.anthropic.claude-opus-5" on runtime).
_PREMIUM_MODEL_MATCHES = [
    s.strip() for s in os.environ.get("PREMIUM_MODEL_MATCHES", "").split(",") if s.strip()
]

_COST_TABLE = os.environ.get("COST_LEDGER_TABLE", "")
_COST_BUDGET = float(os.environ.get("COST_BUDGET_USD", "0") or 0)
_COST_WINDOW = int(os.environ.get("COST_WINDOW_SECONDS", "60") or 60)

# --- governance config (runtime state, read from DynamoDB) -------------------
_CONFIG_TABLE = os.environ.get("CONFIG_TABLE", "")
_CONFIG_TTL = int(os.environ.get("CONFIG_CACHE_TTL_SECONDS", "10") or 10)
# How long a per-request DECISION# record survives. This is the admin console's history
# horizon, not an internal detail — see config.DECISION_RECORD_TTL_SECONDS.
_DECISION_TTL = int(os.environ.get("DECISION_RECORD_TTL_SECONDS", "86400") or 86400)
# Module-scope cache survives across warm invocations, so the steady-state cost of
# the config layer is roughly one table scan per TTL per container — not per request.
_config_cache: dict = {"items": None, "fetched_at": 0.0}
try:
    _MODEL_PRICES = json.loads(os.environ.get("MODEL_PRICES_JSON", "{}"))
except Exception:  # noqa: BLE001
    _MODEL_PRICES = {}
try:
    _OUTPUT_PRICES = json.loads(os.environ.get("MODEL_OUTPUT_PRICES_JSON", "{}"))
except Exception:  # noqa: BLE001
    _OUTPUT_PRICES = {}
_DEFAULT_PRICE = 0.003
_DEFAULT_OUTPUT_PRICE = 0.015

# --- real prices, refreshed daily from the AWS Price List API ----------------
# MODEL_PRICES_JSON / MODEL_OUTPUT_PRICES_JSON above are now only a FALLBACK for a model
# the Price List API does not publish. They were measurably wrong: claude-opus-5 was
# priced at 0.015/0.075 against real rates of 0.005/0.025.
_PRICING_TABLE = os.environ.get("PRICING_TABLE", "")
_PRICING_TTL = int(os.environ.get("PRICING_CACHE_TTL_SECONDS", "300") or 300)
_PRICING_STALE_AFTER = int(os.environ.get("PRICING_STALE_AFTER_SECONDS", "129600") or 129600)
_price_cache: dict = {"rows": {}}

# --- FAIL-CLOSED MACHINERY ---------------------------------------------------
# MEASURED GATEWAY BEHAVIOUR (undocumented; see docs/FINDINGS.md):
#
#   interceptor THROTTLED (cannot be invoked)  -> gateway returns 400   FAIL CLOSED
#   interceptor RAISES (unhandled exception)   -> gateway returns 400   FAIL CLOSED
#   interceptor TIMES OUT                      -> gateway returns 200   FAIL *OPEN*
#
# The last row is the whole reason this section exists. A timeout is the failure mode
# that actually happens in production — a slow ApplyGuardrail, a DynamoDB latency spike,
# a cold start under load — and it is the one the platform resolves by letting the
# request through UNGOVERNED. There is no gateway knob to change that.
#
# So the invariant this file must hold is:
#
#       THE INTERCEPTOR MUST NEVER BE KILLED BY THE PLATFORM.
#       IT MUST ALWAYS RETURN A VERDICT ITSELF, AND THAT VERDICT DEFAULTS TO DENY.
#
# Two mechanisms enforce it:
#   1. Every dependency call gets an explicit connect/read timeout, so one hung service
#      cannot consume the whole invocation budget.
#   2. A self-imposed deadline is checked BEFORE each control. If there is not enough
#      time left to evaluate it, we deny on our own terms instead of being killed.
#
# Corollary, and it is counter-intuitive: the `except: return _passthrough()` handlers
# this file used to have were WORSE than having no handler at all. An unhandled exception
# fails closed at the gateway; catching it and passing through converts a safe platform
# default into an unsafe one. They are all gone.
_SAFETY_MARGIN_MS = int(os.environ.get("INTERCEPTOR_SAFETY_MARGIN_MS", "2000") or 2000)

# Per-control time estimates, used to decide whether there is room to proceed. Generous
# on purpose: denying slightly early is the correct bias for a fail-closed control.
_COST_MS = {"config": 2500, "rate": 2500, "charge": 2500, "guardrail": 6000}

_DDB_CFG = BotoConfig(
    connect_timeout=1,
    read_timeout=2,
    retries={"max_attempts": 2, "mode": "standard"},
)
# ApplyGuardrail is the slow dependency. ONE attempt only — a retry here would double
# the worst case and the deadline check is a better backstop than a second try.
_BEDROCK_CFG = BotoConfig(
    connect_timeout=2,
    read_timeout=5,
    retries={"max_attempts": 1, "mode": "standard"},
)

_bedrock = boto3.client("bedrock-runtime", region_name=_REGION, config=_BEDROCK_CFG)
_ddb = boto3.client("dynamodb", region_name=_REGION, config=_DDB_CFG)


class _OutOfTime(Exception):
    """Not enough invocation budget left to evaluate a control safely.

    Raised rather than returned so it cannot be accidentally ignored by a caller that
    forgets to check a return value — the failure mode that produced three bypasses.
    """


class _Deadline:
    """Tracks how much of the invocation budget is left.

    `context.get_remaining_time_in_millis()` is the only honest source: it accounts for
    cold-start time already spent, which a `time.time()` baseline taken inside the
    handler does not.
    """

    def __init__(self, context):
        self._context = context
        self._fallback_ms = 15000

    def remaining_ms(self) -> int:
        getter = getattr(self._context, "get_remaining_time_in_millis", None)
        if getter is None:
            return self._fallback_ms
        try:
            return int(getter())
        except Exception:  # noqa: BLE001
            return self._fallback_ms

    def ensure(self, control: str) -> None:
        """Fail closed if `control` cannot be completed within the safety margin."""
        need = _COST_MS.get(control, 2000) + _SAFETY_MARGIN_MS
        left = self.remaining_ms()
        if left < need:
            raise _OutOfTime(
                f"{left}ms left, {control} needs ~{need}ms including a "
                f"{_SAFETY_MARGIN_MS}ms margin"
            )


# --- BREAK GLASS -------------------------------------------------------------
# A fail-closed governance plane is one bug away from a total inference outage. That is
# an acceptable trade only if recovery does not require a code deploy.
#
# Config row (DEFAULT, BREAKGLASS) with enabled=true bypasses enforcement. It is
# deliberately awkward to leave on: every bypassed request writes an audit record at
# `decision=breakglass_bypass`, and the reason field is required to be set by whoever
# flips it, so the log says who decided and why.
_BREAKGLASS_KIND = "BREAKGLASS"

# bedrock-runtime passthrough paths: /model/<modelId>/<verb> where verb is one of
# invoke, invoke-with-response-stream, converse, converse-stream, ...
#
# DELIBERATELY GENERIC IN THE VERB. An earlier version matched only `/invoke`, which
# silently failed to resolve the model for `/converse` — and an unresolvable model meant
# the allow/deny globs matched nothing, so entitlement was BYPASSED. Verified: a
# standard-tier user reached a premium model through /converse and /converse-stream.
# Matching any verb means a NEW runtime operation still resolves its model instead of
# quietly opening a hole. See docs/FINDINGS.md.
_RUNTIME_PATH = re.compile(r"/model/([^/]+)/([A-Za-z0-9_-]+)")

# Runtime verbs that stream. Only used for labelling; governance does not depend on it.
_STREAMING_VERBS = {"invoke-with-response-stream", "converse-stream"}

# Keys whose presence means "binary or externally-referenced media". We record that a
# request carried them but never walk into them: they are not text, and base64 image
# bytes would blow up both the guardrail call and the audit record.
_OPAQUE_KEYS = ("bytes", "source", "s3Location", "s3_location")

# Keys worth walking into when harvesting caller-supplied text. Everything else in a
# content block (type discriminators, tool-use ids, mime types) is noise that would
# pollute the guardrail input and inflate the prompt digest.
_TEXT_BEARING_KEYS = (
    "text",            # Anthropic + OpenAI + Converse content blocks
    "content",         # nested content lists
    "toolResult",      # Converse tool result  <-- injection arrives here
    "tool_result",     # Anthropic tool result
    "toolUse",         # Converse tool call
    "input",           # tool arguments, Responses API input
    "arguments",       # OpenAI function-call arguments
    "json",            # Converse toolResult json payload
    "parts",           # OpenAI multi-part content
    "guardContent",    # Converse explicit guard block
)


def _prompt_digest(text_units: list) -> dict:
    """Content fingerprint WITHOUT retaining the content.

    A security reviewer needs to correlate requests, spot repeats and prove a payload
    was not altered. A SHA-256 over the caller-authored text plus its size does all
    three. The text itself is only included when explicitly opted in, because an audit
    log is the worst place to accumulate prompt data by default.
    """
    joined = "\n".join(text_units)
    info = {
        "prompt_sha256": hashlib.sha256(joined.encode("utf-8")).hexdigest(),
        "prompt_chars": len(joined),
        "prompt_units": len(text_units),
    }
    if _AUDIT_PROMPTS and joined:
        info["prompt_text"] = [u[:_AUDIT_PROMPT_MAX] for u in text_units]
        info["prompt_truncated"] = any(len(u) > _AUDIT_PROMPT_MAX for u in text_units)
    return info


def _surface_of(path: str) -> str:
    """Which upstream surface this request is bound for, from the gateway path."""
    if _RUNTIME_PATH.search(path or ""):
        return "bedrock-runtime"
    return "bedrock-mantle"


def _api_shape_of(path: str, body: dict) -> str:
    """The request's API shape, so the audit log records WHAT was called, not just where.

    Governance is shape-independent, but an investigator still wants to know which
    contract the caller used — the shapes differ in where the prompt, the model and the
    output ceiling live, and a mislabelled shape is the first sign that path handling
    has drifted behind the API surface.
    """
    p = (path or "").lower()
    if "/chat/completions" in p:
        return "openai.chat.completions"
    if "/v1/responses" in p:
        return "openai.responses"
    if "/v1/messages" in p:
        return "anthropic.messages"
    m = _RUNTIME_PATH.search(p)
    if m:
        return f"bedrock.{m.group(2).replace('-', '_')}"
    # Fall back to inferring from the body when the path is unfamiliar. The trailing `?`
    # marks a GUESS — if these show up in the audit log, a real shape is unaccounted for.
    if "toolConfig" in body or "inferenceConfig" in body:
        return "bedrock.converse?"
    if "messages" in body:
        return "anthropic.messages?"
    if "input" in body:
        return "openai.responses?"
    if "prompt" in body:
        return "legacy.completions?"
    return "unknown"


def _harvest(node, out: list, depth: int = 0) -> None:
    """Recursively collect caller-supplied text from a content node.

    Structure-driven rather than shape-driven, so a body layout this code has never
    seen still yields its text instead of yielding nothing. Bounded on depth and count
    because the request is attacker-influenced.
    """
    if depth > 12 or len(out) > 400:
        return
    if isinstance(node, str):
        if node.strip():
            out.append(node)
        return
    if isinstance(node, (int, float, bool)) or node is None:
        return
    if isinstance(node, list):
        for item in node:
            _harvest(item, out, depth + 1)
        return
    if isinstance(node, dict):
        # Media blobs and external references: presence only, never contents.
        if any(k in node for k in _OPAQUE_KEYS):
            return
        for key in _TEXT_BEARING_KEYS:
            if key in node:
                _harvest(node[key], out, depth + 1)
        return


def _tool_info(body: dict) -> dict:
    """Tool definitions declared and tool calls present, for the audit record.

    Tools are part of what a caller submits and part of what governance should be able
    to answer questions about ("who gave the model a shell?"), so the names are always
    recorded even when prompt text is not.
    """
    specs, invoked, schemas = [], [], []

    # Converse: toolConfig.tools[].toolSpec.name
    for t in ((body.get("toolConfig") or {}).get("tools") or []):
        if isinstance(t, dict):
            spec = t.get("toolSpec") or {}
            if spec.get("name"):
                specs.append(str(spec["name"]))
                if _AUDIT_TOOL_SCHEMAS:
                    schemas.append({"name": str(spec["name"]),
                                    "description": str(spec.get("description") or "")[:300],
                                    "schema": json.dumps(spec.get("inputSchema"))[:1000]})

    # Anthropic: tools[].name  ·  OpenAI: tools[].function.name
    for t in (body.get("tools") or []):
        if not isinstance(t, dict):
            continue
        fn = t.get("function") if isinstance(t.get("function"), dict) else None
        name = t.get("name") or (fn or {}).get("name")
        if not name:
            continue
        specs.append(str(name))
        if _AUDIT_TOOL_SCHEMAS:
            src = fn or t
            schemas.append({"name": str(name),
                            "description": str(src.get("description") or "")[:300],
                            "schema": json.dumps(src.get("input_schema")
                                                 or src.get("parameters"))[:1000]})

    # Tool CALLS anywhere in the transcript, both surfaces' spellings.
    def _walk(node, depth=0):
        if depth > 10:
            return
        if isinstance(node, list):
            for i in node:
                _walk(i, depth + 1)
        elif isinstance(node, dict):
            for key in ("toolUse", "tool_use"):
                if isinstance(node.get(key), dict) and node[key].get("name"):
                    invoked.append(str(node[key]["name"]))
            if isinstance(node.get("function"), dict) and node["function"].get("name"):
                invoked.append(str(node["function"]["name"]))
            for v in node.values():
                _walk(v, depth + 1)

    _walk(body.get("messages"))
    out = {}
    if specs:
        out["tool_specs"] = sorted(set(specs))
        out["tool_spec_count"] = len(set(specs))
    if invoked:
        out["tool_invocations"] = sorted(set(invoked))
    if schemas:
        # Opt-in: input schemas often embed internal field names, endpoints and example
        # values, so names alone are the safe default.
        out["tool_schemas"] = schemas
    return out


def _normalize(path: str, body: dict) -> dict:
    """Reduce ANY accepted request shape to the few facts governance needs.

    THIS FUNCTION IS THE FIX FOR A PROVEN BYPASS. Governance previously read the model,
    the prompt and the output ceiling with per-shape field lookups; a shape that spelled
    them differently produced an empty model and no prompt text, which meant entitlement
    matched nothing and the guardrail had nothing to scan. `/converse` did exactly that.

    Returns
    -------
    model              resolved id, or "" if it could not be determined
    model_source       "path" | "body" | ""   (how it was resolved)
    api_shape          canonical shape label
    surface            bedrock-runtime | bedrock-mantle
    verb               runtime operation, when the path carries one
    streaming          whether the caller asked for a stream
    text_units         every caller-supplied text run, INCLUDING tool results
    max_output_tokens  declared output ceiling, across all spellings
    tools              tool specs + invocations for the audit record
    """
    path = path or ""
    body = body if isinstance(body, dict) else {}

    # ---- model + verb -------------------------------------------------------
    model, source, verb = "", "", ""
    m = _RUNTIME_PATH.search(path)
    if m:
        model, source, verb = m.group(1), "path", m.group(2)
    elif body.get("model"):
        model, source = str(body["model"]), "body"

    # ---- caller-supplied text ---------------------------------------------
    units: list[str] = []
    # System prompt, every spelling: Anthropic `system` (str|blocks), Converse
    # `system` ([{text}]), Responses `instructions`, legacy `prompt`.
    for key in ("system", "instructions", "prompt"):
        if key in body:
            _harvest(body[key], units)

    # Conversation turns. Assistant-authored content is skipped — prompt injection
    # lives in what enters the model, and that includes TOOL RESULTS, which arrive on
    # user-role turns and were previously missed entirely.
    for msg in (body.get("messages") or []):
        if isinstance(msg, dict) and msg.get("role") != "assistant":
            _harvest(msg.get("content"), units)

    # Responses API `input`: bare string, or items each carrying `content`.
    inp = body.get("input")
    if isinstance(inp, str):
        _harvest(inp, units)
    elif isinstance(inp, list):
        for item in inp:
            if isinstance(item, dict) and item.get("role") == "assistant":
                continue
            _harvest(item, units)

    # De-duplicate while preserving order: repeated blocks add guardrail cost, not signal.
    seen, deduped = set(), []
    for u in units:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    # ---- declared output ceiling ------------------------------------------
    max_out = 0
    for key in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
        v = body.get(key)
        if isinstance(v, (int, float)) and v > 0:
            max_out = int(v)
            break
    if not max_out:
        # Converse nests it, which is why cost reservation silently did not happen
        # for Converse requests before this normalizer existed.
        v = (body.get("inferenceConfig") or {}).get("maxTokens")
        if isinstance(v, (int, float)) and v > 0:
            max_out = int(v)

    return {
        "model": model,
        "model_source": source,
        "api_shape": _api_shape_of(path, body),
        "surface": _surface_of(path),
        "verb": verb,
        "streaming": verb in _STREAMING_VERBS or bool(body.get("stream")),
        "text_units": deduped,
        "max_output_tokens": max_out,
        "tools": _tool_info(body),
    }


def _audit(**fields) -> None:
    """Emit one audit record. Must never raise into the request path."""
    try:
        rec = {
            "audit": True,
            "schema": _AUDIT_SCHEMA,
            "stage": "REQUEST",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        rec.update({k: v for k, v in fields.items() if v is not None})
        print(json.dumps(rec, default=str, separators=(",", ":")))
    except Exception as exc:  # noqa: BLE001
        print(f"audit emit failed ({exc})")


def _decode_jwt_claims(auth_header: str) -> dict:
    """Best-effort JWT payload decode (no signature check; the gateway already
    validated the token before invoking this interceptor)."""
    if not auth_header:
        return {}
    token = auth_header.split()[-1]
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:  # noqa: BLE001
        return {}


def _apply_guardrail(text_units: list[str], guardrail_id: str,
                     guardrail_version: str) -> dict:
    """Call Bedrock ApplyGuardrail on the INPUT content. Returns the raw response.

    BOTH the id and the version come from the resolved config row, so different
    users/groups can be held to different guardrails.

    ⚠️ THE VERSION MUST BE A PARAMETER, NOT A MODULE GLOBAL. It used to read the
    `GUARDRAIL_VERSION` env var, which CDK bakes from the guardrail THIS STACK creates.
    Once the admin console could bind any guardrail in the account, that combination
    became incoherent: the id came from policy while the version came from a different
    guardrail's deploy-time state. Every guardrail in the development account happened
    to sit at `DRAFT`, so it looked fine and was not.

    Two ways it fails once someone binds a PUBLISHED guardrail:
      * the version does not exist on that guardrail -> ApplyGuardrail raises ->
        fail closed -> a 403 outage for every principal in that scope;
      * the version exists but is not the one the admin previewed -> we silently
        enforce a different content policy than the console displayed.

    Neither is acceptable, and the second is worse.
    """
    # ApplyGuardrail takes a list of content blocks; each text block is qualified
    # as `query`/`guard_content`. We mark caller content as guardable input.
    content = [{"text": {"text": t, "qualifiers": ["guard_content"]}} for t in text_units]
    return _bedrock.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion=guardrail_version or _GUARDRAIL_VERSION,
        source="INPUT",
        content=content,
    )


def _block_response(reason: str, detail: dict) -> dict:
    payload = {
        "error": {
            "type": "guardrail_intervention",
            "message": reason,
            "detail": detail,
        }
    }
    body_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return {
        "interceptorOutputVersion": "1.0",
        "http": {
            "transformedGatewayResponse": {
                "statusCode": 403,
                "contentType": "application/json",
                "headers": {"X-Guardrail-Intervention": "true"},
                "body": body_b64,
            }
        },
    }


def _passthrough() -> dict:
    # Empty http object = pass the request through unchanged.
    return {"interceptorOutputVersion": "1.0", "http": {}}


def _closed_response(code: str, message: str, detail: dict | None = None,
                     status: int = 403) -> dict:
    """The deny we return when governance could not be evaluated.

    Distinct from _block_response (a guardrail verdict) and _entitlement_block (a policy
    verdict) because it means something different to whoever receives it: not "you are
    not allowed to do this" but "we could not establish whether you are allowed, so we
    refused". That distinction is what makes the audit log actionable — a spike of
    `governance_unavailable` is an operational incident, not a wave of policy violations.
    """
    payload = {
        "error": {
            "type": code,
            "message": message,
            "detail": {**(detail or {}), "fail_closed": True},
        }
    }
    body_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return {
        "interceptorOutputVersion": "1.0",
        "http": {
            "transformedGatewayResponse": {
                "statusCode": status,
                "contentType": "application/json",
                "headers": {"X-Governance": "fail-closed"},
                "body": body_b64,
            }
        },
    }


def _load_config() -> dict:
    """Load all governance config rows, cached for CONFIG_CACHE_TTL_SECONDS.

    Returns {(pk, sk): {attr: value}}. The table is small (a handful of rows per
    scope), so a Scan is the right call — simpler and cheaper than many GetItems,
    and it lets one read serve every lookup this request needs.

    FAILS CLOSED. This one mattered most of all the fail-open paths, and it was the
    least obvious: the config table is where the DENY rules live, so "use an empty
    config on error" did not mean "no policy", it meant **no denials** — every model
    allowed, every budget unset, every guardrail unselected. A transient DynamoDB blip
    silently disabled governance.

    On error we now serve a STALE cache if we have one (policy that is ten seconds old
    is vastly better than no policy) and raise otherwise, which the handler converts
    into a 403.
    """
    import time as _time

    now = _time.time()
    if (
        _config_cache["items"] is not None
        and now - _config_cache["fetched_at"] < _CONFIG_TTL
    ):
        return _config_cache["items"]

    items: dict = {}
    try:
        paginator = _ddb.get_paginator("scan")
        for page in paginator.paginate(TableName=_CONFIG_TABLE):
            for raw in page.get("Items", []):
                pk = raw.get("pk", {}).get("S", "")
                sk = raw.get("sk", {}).get("S", "")
                items[(pk, sk)] = raw
    except Exception as exc:  # noqa: BLE001
        stale = _config_cache["items"]
        if stale is not None:
            age = int(now - _config_cache["fetched_at"])
            print(f"config load failed ({exc}); SERVING STALE CACHE age={age}s "
                  f"(degraded, but policy is still applied)")
            # Do NOT advance fetched_at: keep retrying on the next request rather than
            # pinning ourselves to stale policy for a full TTL.
            return stale
        print(f"config load failed ({exc}) and no cache to fall back on; failing closed")
        raise

    _config_cache["items"] = items
    _config_cache["fetched_at"] = now
    return items


def _breakglass() -> dict:
    """Resolve the break-glass bypass row, if an administrator has set one.

    Returns {"enabled": bool, "reason": str, "set_by": str}.

    Read on the same cached scan as everything else, so enabling it takes effect within
    the config TTL (~10s) and needs no deployment. That is the entire point: a
    fail-closed plane is only an acceptable design if an operator can turn it off faster
    than they can ship code.
    """
    row = _load_config().get(("DEFAULT", _BREAKGLASS_KIND))
    if not row:
        return {"enabled": False, "reason": "", "set_by": ""}
    return {
        "enabled": bool(row.get("enabled", {}).get("BOOL", False)),
        "reason": row.get("reason", {}).get("S", "") or "(no reason recorded)",
        "set_by": row.get("set_by", {}).get("S", "") or "(unknown)",
    }


def _scope_chain(claims: dict) -> list:
    """Most-specific-first list of scopes to resolve config against.

    USER#<username>  ->  GROUP#<g> (each, in claim order)  ->  DEFAULT

    `TIER#` is GONE. Group membership is the only identity axis now; a per-user row
    overrides a per-group row, which overrides the global default.

    ⚠️ KNOWN LIMITATION — MULTI-GROUP ORDER IS NOT DEFINED BY US. Groups are walked in the
    order the ACCESS TOKEN presents them, and `_resolve` takes the first row it finds. So for
    a user in several groups that each carry a row of the same kind, the winner is whichever
    group Cognito happened to list first. Measured: `alice` is declared
    `[ai-platform, ml-research]` with precedence 1 and 2, and the token presents
    `['ml-research', 'ai-platform']` — reversed from the declaration, and NOT ascending by
    precedence. Nothing here sorts or validates that ordering.

    This is latent rather than broken today only because a single group carries a row of any
    given kind, and `_resolve` skips scopes that have no row for the kind being resolved. It
    becomes live the moment two of a user's groups both have one.

    Do NOT read this as "most restrictive wins" — it is "first listed wins", so adding someone
    to a more restrictive group may not restrict them. Candidate fixes (an explicit `priority`
    attribute, or merging all matching scopes deny-wins) are written up in docs/FINDINGS.md
    under the multi-group future enhancement. Until then the safe rule is one group per kind,
    with `USER#` rows for exceptions.
    """
    chain = []
    username = claims.get("username") or claims.get("cognito:username")
    if username:
        chain.append(f"USER#{username}")
    groups = claims.get("cognito:groups") or []
    if isinstance(groups, str):
        groups = [groups]
    for g in groups:
        chain.append(f"GROUP#{g}")
    chain.append("DEFAULT")
    return chain


def _resolve(claims: dict, kind: str) -> dict:
    """First matching config row for `kind` walking the scope chain."""
    items = _load_config()
    for scope in _scope_chain(claims):
        row = items.get((scope, kind))
        if row:
            return {"scope": scope, "row": row}
    return {}


def _strs(row: dict, attr: str) -> list:
    return [v.get("S", "") for v in (row.get(attr, {}).get("L") or [])]


def _matches_any(model: str, globs: list) -> bool:
    return any(fnmatch.fnmatch(model, g) for g in globs if g)


def _model_allowed(claims: dict, model: str) -> dict:
    """Evaluate MODELS config for this principal.

    deny wins over allow. An empty/absent allow list means "allow everything".
    Returns {allowed, scope, reason}.
    """
    found = _resolve(claims, "MODELS")
    if not found or not model:
        return {"allowed": True, "scope": "(none)", "reason": "no MODELS config"}
    row = found["row"]
    deny = _strs(row, "deny")
    allow = _strs(row, "allow")
    if deny and _matches_any(model, deny):
        return {"allowed": False, "scope": found["scope"], "reason": "matched deny list"}
    if allow and not _matches_any(model, allow):
        return {"allowed": False, "scope": found["scope"], "reason": "not in allow list"}
    return {"allowed": True, "scope": found["scope"], "reason": "permitted"}


def _num(row: dict, attr: str, default: float = 0.0) -> float:
    """Read a DynamoDB numeric attribute, tolerating absence/garbage."""
    try:
        return float(row.get(attr, {}).get("N", default))
    except Exception:  # noqa: BLE001
        return float(default)


def _budget_for(claims: dict) -> dict:
    """Resolved cost budget as INDEPENDENT daily + monthly caps.

    Either cap can deny. A cap of 0 (or absent) means that window is not enforced, so a
    scope may set a daily cap, a monthly cap, both, or neither.

    BACKWARD COMPATIBLE with the original single-window schema (`budget_usd` +
    `window_seconds`): if a row carries only those, the amount is treated as the DAILY
    cap. New rows use `daily_budget_usd` / `monthly_budget_usd`. The env-var fallback
    (the demo's tiny per-window budget) is likewise mapped onto the daily cap so a
    deployment with no BUDGET row still enforces something.

    Returns:
        {daily, monthly, scope}  -- daily/monthly are USD caps (0 == not enforced).
    """
    found = _resolve(claims, "BUDGET")
    if not found:
        # No row: fall back to the demo env budget as a DAILY cap. Monthly unset.
        return {"daily": _COST_BUDGET, "monthly": 0.0, "scope": "(env default)"}
    row = found["row"]
    daily = _num(row, "daily_budget_usd", 0.0)
    monthly = _num(row, "monthly_budget_usd", 0.0)
    # Legacy single-window row: no daily/monthly attrs, but a budget_usd is present.
    if daily <= 0 and monthly <= 0 and "budget_usd" in row:
        daily = _num(row, "budget_usd", 0.0)
    return {"daily": daily, "monthly": monthly, "scope": found["scope"]}


def _cost_buckets(now: int | None = None) -> dict:
    """The daily and monthly ledger bucket suffixes for `now` (UTC).

    Daily  -> 'D#YYYYMMDD'  (calendar day, not a rolling 24h window)
    Monthly-> 'M#YYYYMM'    (calendar month)

    Calendar-aligned buckets (rather than epoch//window) are what make "daily" and
    "monthly" mean what an operator expects, and they let the out-of-band rollup and the
    admin console address the exact same rows without knowing a window length.
    """
    import time as _time
    from datetime import datetime, timezone

    ts = now if now is not None else int(_time.time())
    dt = datetime.fromtimestamp(ts, timezone.utc)
    return {
        "day": f"D#{dt.strftime('%Y%m%d')}",
        "month": f"M#{dt.strftime('%Y%m')}",
    }


def _claim_request(request_id: str) -> dict:
    """Idempotency guard. Returns {"first": bool, "verdict": dict|None}.

    WHY THIS IS HERE. The AgentCore devguide states plainly:

        "The gateway may retry requests to interceptor Lambda functions in case of
         failures or timeouts. Ensure your interceptor logic can handle duplicate
         invocations safely."

    Both mutating controls in this file are `ADD` operations — `ADD tokens/requests` on
    the rate counter and `ADD spend` on the ledger. Neither is idempotent, so a single
    gateway retry charges a user twice and consumes their rate allowance twice. Under a
    tight demo budget that is the difference between a 200 and a spurious 429.

    Mechanism: a conditional PutItem on a marker row. Winning the condition means this is
    the first attempt. Losing it means we are a retry, and we replay the stored verdict
    instead of re-charging.

    ASSUMPTION, and it is unverified: that the gateway reuses the same REQUEST_ID across
    retries of the same caller request. If it mints a fresh one per attempt this guard
    silently does nothing — it never makes things worse, but it would not help either.
    Inducing a real gateway retry on demand is not something the API exposes, so this is
    documented rather than proven. Treat it as defence, not a guarantee.
    """
    if not (_COST_TABLE and request_id):
        return {"first": True, "verdict": None}
    import time as _time
    pk = f"SEEN#{request_id}"
    try:
        _ddb.put_item(
            TableName=_COST_TABLE,
            Item={"pk": {"S": pk},
                  "ttl": {"N": str(int(_time.time()) + 900)},
                  "claimed_at": {"N": str(int(_time.time()))}},
            ConditionExpression="attribute_not_exists(pk)",
        )
        return {"first": True, "verdict": None}
    except _ddb.exceptions.ConditionalCheckFailedException:
        pass
    except Exception as exc:  # noqa: BLE001
        # Cannot establish whether this is a retry. Proceed as if first: the cost of a
        # rare double-charge is smaller than denying a legitimate request, and the
        # controls themselves still apply.
        print(f"idempotency claim failed ({exc}); treating as first attempt")
        return {"first": True, "verdict": None}

    # Lost the race -> this is a retry. Replay whatever the first attempt concluded.
    try:
        got = _ddb.get_item(TableName=_COST_TABLE, Key={"pk": {"S": pk}},
                            ConsistentRead=True).get("Item") or {}
        stored = got.get("verdict", {}).get("S")
        if stored:
            print(f"RETRY of {request_id}: replaying stored verdict, not re-charging")
            return {"first": False, "verdict": json.loads(stored)}
        # First attempt claimed the id but never recorded an outcome, i.e. it is the one
        # that timed out. Fail closed: we cannot know whether it already charged.
        print(f"RETRY of {request_id}: first attempt left no verdict; failing closed")
        return {"first": False, "verdict": {"__deny__": "in_flight"}}
    except Exception as exc:  # noqa: BLE001
        print(f"idempotency replay read failed ({exc}); failing closed")
        return {"first": False, "verdict": {"__deny__": "replay_failed"}}


def _record_verdict(request_id: str, verdict: dict) -> None:
    """Store this request's outcome on the marker row so a retry can replay it."""
    if not (_COST_TABLE and request_id):
        return
    try:
        _ddb.update_item(
            TableName=_COST_TABLE,
            Key={"pk": {"S": f"SEEN#{request_id}"}},
            UpdateExpression="SET verdict = :v",
            ExpressionAttributeValues={":v": {"S": json.dumps(verdict)[:3000]}},
        )
    except Exception as exc:  # noqa: BLE001
        # Non-fatal: worst case a retry fails closed instead of replaying.
        print(f"could not store verdict for {request_id} ({exc})")


def _ratelimit_for(claims: dict) -> dict:
    """Resolved rate limit, and — critically — whether it is POOLED.

    `pooled` is the whole reason this control moved off native rate limits. A native
    limit keyed on `jwt.sub` gives every member of a group their own allowance; there is
    no way to say "this team shares 6000 tokens a minute". Here the counter key is the
    SCOPE THAT MATCHED, so a `GROUP#` row is naturally shared while a `USER#` row is
    naturally per-person.
    """
    found = _resolve(claims, "RATELIMIT")
    if not found:
        return {"tokens": _RATE_TOKENS, "requests": _RATE_REQUESTS,
                "window": _RATE_WINDOW, "scope": "(env default)", "pooled": False}
    row = found["row"]

    def num(attr, default):
        try:
            return int(float(row.get(attr, {}).get("N", default)))
        except Exception:  # noqa: BLE001
            return default

    scope = found["scope"]
    pooled = row.get("pooled", {}).get("BOOL")
    if pooled is None:
        # Sensible default: a group-scoped limit is a team allowance; a user-scoped or
        # global one is per person. An admin can override either way.
        pooled = scope.startswith("GROUP#")
    return {
        "tokens": num("tokens_per_window", _RATE_TOKENS),
        "requests": num("requests_per_window", _RATE_REQUESTS),
        "window": num("window_seconds", _RATE_WINDOW),
        "scope": scope,
        "pooled": bool(pooled),
    }


def _check_rate(user_sub: str, cfg: dict, est_tokens: int) -> dict:
    """Count this request against the resolved rate limit and report the verdict.

    Fixed window, matching the cost ledger's model. Chosen for the same reason: one
    atomic ADD per request and a TTL that cleans up after itself, versus a sorted-set
    sliding window that needs either a read-modify-write or a second data store. The
    trade-off is the usual fixed-window burst at a boundary — stated, not hidden.

    Counts are incremented BEFORE dispatch on the prompt estimate, then corrected by the
    RESPONSE interceptor once real output tokens are known, so generation counts toward
    the limit rather than escaping it the way a native input-only limit does.
    """
    window = max(1, cfg["window"])
    bucket = int(time.time()) // window
    # Pooled -> the counter belongs to the SCOPE. Not pooled -> to the principal.
    subject = cfg["scope"] if cfg["pooled"] else f"USER#{user_sub}"
    pk = f"RATE#{subject}#{bucket}"

    # FAILS CLOSED: no try/except. An exception here propagates to the handler, which
    # denies. Previously this returned {"exceeded": False} on error, so a DynamoDB blip
    # silently removed the rate limit — the control looked healthy and enforced nothing.
    # ⚠️ THE TTL ATTRIBUTE MUST BE `ttl`. The ledger table declares
    # `time_to_live_attribute="ttl"`, and DynamoDB only reaps items via THAT attribute —
    # a timestamp under any other name is just an ordinary number.
    #
    # This wrote `expires_at` for a while, so these counters were never collected. It was
    # invisible because it breaks nothing that is read: the window bucket is part of the
    # key, so a stale row is never consulted again and enforcement stayed correct. What it
    # did instead was leak storage without bound — one row per subject per window, forever,
    # which at a 60s window is 1440 rows per subject per day — and inflate every full-table
    # scan the admin console does. Observed on the live table: rows 12 hours past their
    # nominal expiry still present.
    #
    # `#t` is an ExpressionAttributeName because `ttl` is a DynamoDB reserved word.
    resp = _ddb.update_item(
        TableName=_COST_TABLE,
        Key={"pk": {"S": pk}},
        UpdateExpression=("ADD tokens :t, requests :r SET #ttl = :e, "
                          "subject = :s"),
        ExpressionAttributeNames={"#ttl": "ttl"},
        ExpressionAttributeValues={
            ":t": {"N": str(max(0, est_tokens))},
            ":r": {"N": "1"},
            ":e": {"N": str(int(time.time()) + window * 3 + 60)},
            ":s": {"S": subject},
        },
        ReturnValues="UPDATED_NEW",
    )
    attrs = resp.get("Attributes", {})
    tokens = int(float(attrs.get("tokens", {}).get("N", 0)))
    requests = int(float(attrs.get("requests", {}).get("N", 0)))

    over_tokens = cfg["tokens"] > 0 and tokens > cfg["tokens"]
    over_requests = cfg["requests"] > 0 and requests > cfg["requests"]
    return {
        "exceeded": bool(over_tokens or over_requests),
        "limit_hit": "tokens" if over_tokens else ("requests" if over_requests else ""),
        "tokens": tokens,
        "requests": requests,
        "tokens_limit": cfg["tokens"],
        "requests_limit": cfg["requests"],
        "bucket": bucket,
        "subject": subject,
        "pooled": cfg["pooled"],
    }


def _rate_block(state: dict, cfg: dict) -> dict:
    """429 with enough detail that a caller can act on it."""
    payload = {
        "error": {
            "type": "rate_limit_exceeded",
            "message": (
                f"Rate limit exceeded on {state.get('limit_hit') or 'usage'}: "
                f"{state.get('tokens')}/{cfg['tokens']} tokens and "
                f"{state.get('requests')}/{cfg['requests']} requests in a "
                f"{cfg['window']}s window. "
                + ("This is a POOLED limit shared across "
                   f"{cfg['scope']}." if cfg["pooled"] else
                   "This is a per-user limit.")
                + " Enforced at the gateway for all upstream surfaces."
            ),
            "detail": {
                "policy_scope": cfg["scope"],
                "pooled": cfg["pooled"],
                "window_seconds": cfg["window"],
                "tokens_used": state.get("tokens"),
                "requests_used": state.get("requests"),
            },
        }
    }
    return {
        "interceptorOutputVersion": "1.0",
        "http": {
            "transformedGatewayResponse": {
                "statusCode": 429,
                "contentType": "application/json",
                "body": base64.b64encode(json.dumps(payload).encode()).decode(),
            }
        },
    }


def _guardrail_for(claims: dict) -> dict:
    """Resolved guardrail selection — this is what makes per-group guardrails work.

    Returns the id AND the version together. They are a PAIR: an id without the version
    it was chosen against is not a complete guardrail selection, because the same id
    serves a mutable `DRAFT` and any number of immutable published versions with
    different content policies. See `_apply_guardrail` for what went wrong when the
    version came from somewhere else.

    A row with no `guardrail_version` resolves to `DRAFT`, which is both the pre-existing
    behaviour for this stack's own guardrail and the only safe guess: DRAFT is the one
    version every guardrail is guaranteed to have.
    """
    found = _resolve(claims, "GUARDRAIL")
    if not found:
        return {"guardrail_id": _GUARDRAIL_ID, "guardrail_version": _GUARDRAIL_VERSION,
                "enabled": bool(_GUARDRAIL_ID), "scope": "(env default)"}
    row = found["row"]
    gid = row.get("guardrail_id", {}).get("S") or _GUARDRAIL_ID
    # Only inherit the env version when the id is also the env default. For any OTHER
    # guardrail the env version describes a different resource, so DRAFT is correct.
    fallback = _GUARDRAIL_VERSION if gid == _GUARDRAIL_ID else "DRAFT"
    ver = row.get("guardrail_version", {}).get("S") or fallback
    enabled = row.get("enabled", {}).get("BOOL")
    if enabled is None:
        enabled = bool(gid)
    return {"guardrail_id": gid, "guardrail_version": ver,
            "enabled": bool(enabled), "scope": found["scope"]}


def _model_price_key(model: str) -> str:
    """Normalize a model id to the pricing table's key.

    Must match `_model_key` in the pricing sync Lambda exactly, so that one row serves
    the mantle id, the runtime cross-region profile and the target-qualified form:
        bedrockprov/anthropic.claude-opus-5 -> claudeopus5
        us.anthropic.claude-opus-5          -> claudeopus5
    """
    if not model:
        return ""
    s = model.split("/")[-1]
    s = re.sub(r"^(us|eu|apac|ap|global)\.", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^[a-z0-9]+\.", "", s, flags=re.IGNORECASE)
    s = re.sub(r"-mantle$", "", s, flags=re.IGNORECASE)
    s = re.sub(r":\d+$", "", s)
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _prices_for(model: str) -> dict:
    """Real per-1K rates for this model, from the pricing table.

    Falls back to the compiled-in constants ONLY when the table has no row — which is a
    reportable condition, not a silent default, because the constants were measurably
    wrong (opus-5 was priced at 3x its real rate before this table existed).

    Cached per container for PRICING_CACHE_TTL_SECONDS: prices change daily at most, so
    a per-request read would be pure waste.
    """
    key = _model_price_key(model)
    now = time.time()
    hit = _price_cache["rows"].get(key)
    if hit and now - hit["at"] < _PRICING_TTL:
        return hit["prices"]

    prices = {
        "input": _price_lookup_fallback(model, _MODEL_PRICES, _DEFAULT_PRICE),
        "output": _price_lookup_fallback(model, _OUTPUT_PRICES, _DEFAULT_OUTPUT_PRICE),
        "cache_read": 0.0,
        "cache_write": 0.0,
        "source": "fallback-constants",
        "stale": False,
    }
    if _PRICING_TABLE and key:
        try:
            got = _ddb.get_item(TableName=_PRICING_TABLE,
                                Key={"model_key": {"S": key}})
            row = got.get("Item")
            if row:
                def num(attr, default=0.0):
                    try:
                        return float(row.get(attr, {}).get("N", default))
                    except Exception:  # noqa: BLE001
                        return default
                refreshed = num("refreshed_at", 0.0)
                prices = {
                    "input": num("input_per_1k", prices["input"]),
                    "output": num("output_per_1k", prices["output"]),
                    "cache_read": num("cache_read_per_1k", 0.0),
                    "cache_write": num("cache_write_per_1k", 0.0),
                    "cache_write_1h": num("cache_write_1h_per_1k", 0.0),
                    "source": row.get("source", {}).get("S", "price-list-api"),
                    "rate_scope": row.get("rate_scope", {}).get("S", ""),
                    "refreshed_at": int(refreshed),
                    # Enforcement continues on the last known rates. Falling back to the
                    # constants here would be the worse error, and falling back to zero
                    # would mean unlimited spend.
                    "stale": bool(refreshed and (now - refreshed) > _PRICING_STALE_AFTER),
                }
            else:
                print(f"PRICING: no row for model_key={key!r} (model={model!r}); "
                      f"using fallback constants")
        except Exception as exc:  # noqa: BLE001
            print(f"PRICING: table read failed ({exc}); using fallback constants")

    _price_cache["rows"][key] = {"at": now, "prices": prices}
    return prices


def _price_lookup_fallback(model: str, table: dict, default: float) -> float:
    for substring, price in table.items():
        if substring in model:
            return float(price)
    return default


def _price_per_1k(model: str) -> float:
    return _prices_for(model)["input"]


def _output_price_per_1k(model: str) -> float:
    """Output pricing, used to RESERVE worst-case generation cost up front."""
    return _prices_for(model)["output"]


def _max_tokens_of(body: dict) -> int:
    """DEPRECATED — superseded by `_normalize()["max_output_tokens"]`.

    Kept only because it documents the trap: this looked complete, but Converse nests
    the ceiling under `inferenceConfig.maxTokens`, so Converse requests reserved NO
    output cost at all. Use the normalizer.
    """
    for key in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
        v = body.get(key)
        if isinstance(v, (int, float)) and v > 0:
            return int(v)
    return 0


def _estimate_prompt_tokens(text_units: list[str]) -> int:
    """Rough prompt-token estimate (~4 chars/token).

    Deliberately approximate: there is no tokenizer in this Lambda. It is good
    enough to demonstrate budget enforcement, and the ledger is the extension
    point for exact accounting (e.g. reconciling against reported usage).
    """
    chars = sum(len(t) for t in text_units)
    return max(1, chars // 4)


def _charge_one(pk: str, cost: float, ttl_seconds: int) -> float:
    """ADD `cost` to one spend counter and return the new total. FAILS CLOSED.

    No try/except: a ledger write that does not land means we do not know what this
    principal has spent, and unknown spend is not a basis for allowing more of it.
    """
    import time as _time
    resp = _ddb.update_item(
        TableName=_COST_TABLE,
        Key={"pk": {"S": pk}},
        UpdateExpression="ADD spend :c SET #t = :ttl",
        ExpressionAttributeNames={"#t": "ttl"},
        ExpressionAttributeValues={
            ":c": {"N": str(cost)},
            ":ttl": {"N": str(int(_time.time()) + ttl_seconds)},
        },
        ReturnValues="UPDATED_NEW",
    )
    return float(resp["Attributes"]["spend"]["N"])


def _charge_and_check(
    user_sub: str, model: str, text_units: list[str], daily: float, monthly: float,
    max_tokens: int = 0
) -> dict:
    """Reserve this request's estimated cost against the DAILY and MONTHLY counters and
    report whether either cap is exceeded.

    Returns {charged, daily_total, monthly_total, daily, monthly, exceeded,
    exceeded_window, sub, day_pk, month_pk}. FAILS CLOSED on any ledger error --
    the underlying writes have no try/except.

    This is a RESERVATION, not a bill: prompt tokens priced for real plus the caller's
    declared `max_tokens` at the output rate. The RESPONSE interceptor reconciles it to
    actuals and `_refund_reservation` reverses it on every denial path.

    Deliberately excludes prompt-cache tokens. Pre-dispatch we cannot know whether a
    block will hit or miss the cache, and a cache read is CHEAPER than plain input, so
    pricing all input at the full rate keeps the reservation an upper bound -- which is
    what an enforcement ceiling has to be. Reconciliation is where cache tiers are
    priced, and it is authoritative.

    NOTE this reserves against the PROMPT plus a declared ceiling. True output tokens are
    unknown pre-dispatch, which is exactly why native token limits cannot bound generation
    spend either. Capturing output cost requires a RESPONSE interceptor, which forfeits
    streaming.
    """
    import time as _time

    # RESERVE, don't just charge the prompt. Output tokens don't exist yet, but the
    # caller declares a ceiling via max_tokens, so we reserve prompt cost + the
    # worst-case output cost. The RESPONSE interceptor then reconciles down to actuals.
    #
    # Why this matters: charging prompt-only would let a burst of large generations
    # overshoot the budget before reconciliation caught up — enforcement would lag by a
    # request. Reserving makes the control pessimistic (it may block slightly early)
    # rather than leaky. This mirrors how the gateway's own token limits work: estimate
    # before forwarding, reconcile after the response.
    tokens = _estimate_prompt_tokens(text_units)
    cost = (tokens / 1000.0) * _price_per_1k(model)
    if max_tokens > 0:
        cost += (max_tokens / 1000.0) * _output_price_per_1k(model)

    now = int(_time.time())
    buckets = _cost_buckets(now)
    day_pk = f"{user_sub}#{buckets['day']}"
    month_pk = f"{user_sub}#{buckets['month']}"

    # Reserve against BOTH calendar counters. The same `cost` is added to each because
    # this one request contributes to both the day's spend and the month's spend. TTLs
    # are sized so the bucket outlives the window it measures: a few extra days for the
    # daily counter, ~40 days for the monthly.
    #
    # FAILS CLOSED throughout: `_charge_one` has no try/except (see its docstring). If
    # only one cap is configured we still write both counters — the un-capped one is
    # harmless bookkeeping the rollup and console can read, and writing it keeps the
    # reconciliation/refund paths symmetric.
    _DAY_TTL = 3 * 86400
    _MONTH_TTL = 40 * 86400
    daily_total = _charge_one(day_pk, cost, _DAY_TTL)
    monthly_total = _charge_one(month_pk, cost, _MONTH_TTL)

    daily_exceeded = daily > 0 and daily_total > daily
    monthly_exceeded = monthly > 0 and monthly_total > monthly
    exceeded_window = "daily" if daily_exceeded else ("monthly" if monthly_exceeded
                                                      else "")
    return {
        "charged": cost,
        "daily_total": daily_total,
        "monthly_total": monthly_total,
        "daily": daily,
        "monthly": monthly,
        "exceeded": daily_exceeded or monthly_exceeded,
        "exceeded_window": exceeded_window,
        # The two counter keys, so reconciliation/refund address exactly these rows even
        # if the response lands after a calendar boundary.
        "day_pk": day_pk,
        "month_pk": month_pk,
        # Needed by _refund_reservation / the pending handoff.
        "sub": user_sub,
    }


def _refund_reservation(state: dict, decision: str) -> None:
    """Reverse this request's cost reservation because a LATER control denied it.

    ⚠️ WHY THIS IS NEEDED. CONTROL 3 reserves prompt cost plus worst-case output cost, and
    then CONTROL 4 (guardrail), the request-shape checks and the deadline can all still
    deny. Without this the caller was billed worst-case output for a request that produced
    NOTHING — and the `cost_budget_exceeded` denial was the worst case of all, charging a
    user again for the request that told them they were over budget, pushing them further
    over and lengthening their own lockout.

    Symmetry with the response side matters here. The rule across both interceptors is:

        no output produced  -> refund
        output produced but unmeasurable -> keep the worst-case charge

    This is the first half. `_settle_reservation` in the RESPONSE interceptor is the
    second, and it also covers denials this function cannot see — Cedar and upstream
    errors both happen after this Lambda has already returned.

    NO `except` HERE, deliberately. If the refund write fails, the exception propagates to
    `handler` and becomes a typed 403: the request is still denied, which is the safe
    outcome. The audit record is written by the caller before `_finish` runs, so the
    reason for the denial survives a refund failure too.
    """
    est = float(state.get("charged") or 0.0)
    day_pk = state.get("day_pk") or ""
    month_pk = state.get("month_pk") or ""
    if est <= 0:
        return
    # Reverse BOTH counters, since the reservation was added to both. No try/except: a
    # failed reversal propagates to `handler` and the request is still denied.
    for pk in (day_pk, month_pk):
        if not pk:
            continue
        _ddb.update_item(
            TableName=_COST_TABLE,
            Key={"pk": {"S": pk}},
            UpdateExpression="ADD spend :d",
            ExpressionAttributeValues={":d": {"N": str(-est)}},
        )
    sub = state.get("sub") or ""
    print(f"REFUND ${est:.6f} to {sub[:8]} (day+month) — denied by {decision}, "
          "no output produced")


def _write_pending(request_id: str, claims: dict, model: str, decision_pk: str,
                   est_cost: float, day_pk: str, month_pk: str) -> None:
    """Hand off identity to the RESPONSE interceptor via the gateway REQUEST_ID.

    WHY THIS EXISTS: the response interceptor sees `gatewayRequest: null` — no JWT, no
    path, no identity — so it cannot attribute output tokens on its own. The only value
    shared by both interceptors for the same request is `REQUEST_ID`, delivered through
    Lambda **client context** (verified identical on both sides). So the request side
    parks what it knows under that key and the response side joins on it.

    Also carries the estimated cost already charged and the decision row's key, so the
    response side can RECONCILE (replace estimate with actuals) rather than double-charge.
    """
    if not _COST_TABLE or not request_id:
        return
    import time as _time

    now = int(_time.time())
    try:
        _ddb.put_item(
            TableName=_COST_TABLE,
            Item={
                "pk": {"S": f"PENDING#{request_id}"},
                "sub": {"S": str(claims.get("sub") or "")},
                "username": {"S": str(claims.get("username")
                                      or claims.get("cognito:username") or "?")},
                "model": {"S": model or "?"},
                "decision_pk": {"S": decision_pk or ""},
                "est_cost": {"N": str(est_cost)},
                # BOTH counter keys, so the RESPONSE interceptor reconciles/settles the
                # exact rows the reservation touched, even across a calendar boundary.
                "day_pk": {"S": day_pk or ""},
                "month_pk": {"S": month_pk or ""},
                # Short TTL: if no response ever arrives, the row simply expires.
                "ttl": {"N": str(now + 900)},
            },
        )
    except Exception as exc:  # noqa: BLE001
        print(f"pending write failed ({exc}); output tokens will go unattributed")


def _record_decision(claims: dict, model: str, path: str, decision: str,
                     status: int, scope: str = "") -> str:
    """Write a per-request decision record.

    WHY THIS EXISTS (verified the hard way): **interceptor short-circuit responses do
    NOT appear in gateway OTEL spans.** Only gateway-native outcomes are spanned —
    Cedar denials (`errorType=user`), rate-limit throttles (`errorType=throttle`) and
    allowed requests. Since model access, guardrails and cost budgets are all enforced
    HERE, the majority of governance decisions would otherwise be invisible to
    telemetry, and any "requests blocked" figure taken from spans would silently
    undercount.

    Records also carry what spans structurally cannot: the end-user identity and the
    model. Stored in the ledger table under a `DECISION#` key prefix with a short TTL.
    Best-effort — never block inference because logging failed.
    """
    import time as _time
    import uuid as _uuid

    if not _COST_TABLE:
        return ""
    now = int(_time.time())
    pk = f"DECISION#{now}#{_uuid.uuid4().hex[:8]}"
    try:
        _ddb.put_item(
            TableName=_COST_TABLE,
            Item={
                "pk": {"S": pk},
                "ts": {"N": str(now)},
                "username": {"S": str(claims.get("username")
                                      or claims.get("cognito:username") or "?")},
                "sub": {"S": str(claims.get("sub") or "")},
                "model": {"S": model or "?"},
                "path": {"S": path or ""},
                "decision": {"S": decision},
                "status": {"N": str(status)},
                "scope": {"S": scope or ""},
                # This TTL IS the admin console's history horizon — the Statistics tab is
                # computed entirely from these rows, so a reaped record is indistinguishable
                # from a request that never happened. Keep it >= the longest range the UI
                # offers, or an admin selecting that range gets an empty table on a healthy
                # system. See config.DECISION_RECORD_TTL_SECONDS.
                "ttl": {"N": str(now + _DECISION_TTL)},
            },
        )
    except Exception as exc:  # noqa: BLE001
        print(f"decision log failed ({exc}); continuing")
        return ""
    return pk


def _budget_block(state: dict, model: str) -> dict:
    win = state.get("exceeded_window") or "daily"
    spent = state["daily_total"] if win == "daily" else state["monthly_total"]
    cap = state["daily"] if win == "daily" else state["monthly"]
    payload = {
        "error": {
            "type": "cost_budget_exceeded",
            "message": (
                f"{win.capitalize()} spend budget exceeded: ${spent:.4f} of "
                f"${cap:.4f}. Enforced at the gateway for all upstream surfaces."
            ),
            "detail": {"model": model, "scope": state.get("scope"),
                       "window": win},
        }
    }
    body_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return {
        "interceptorOutputVersion": "1.0",
        "http": {
            "transformedGatewayResponse": {
                "statusCode": 429,
                "contentType": "application/json",
                "headers": {"X-Cost-Budget": "exceeded"},
                "body": body_b64,
            }
        },
    }


def _entitlement_block(model: str, verdict: dict) -> dict:
    payload = {
        "error": {
            "type": "model_access_denied",
            "message": (f"Access to model '{model}' is denied by policy "
                        f"({verdict.get('reason')}). Enforced at the gateway for all "
                        "upstream surfaces."),
            "detail": {"policy_scope": verdict.get("scope")},
        }
    }
    body_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return {
        "interceptorOutputVersion": "1.0",
        "http": {
            "transformedGatewayResponse": {
                "statusCode": 403,
                "contentType": "application/json",
                "headers": {"X-Model-Entitlement": "denied"},
                "body": body_b64,
            }
        },
    }


def handler(event, context):
    """Thin fail-closed wrapper. ALL governance logic lives in `_govern`.

    The split exists so there is exactly one place that can decide what happens when
    governance cannot be evaluated, and it is impossible for a new control added inside
    `_govern` to accidentally introduce a fail-open path: anything it raises lands here
    and becomes a deny.

    Note what this wrapper deliberately does NOT do: it does not catch an exception and
    pass the request through. An unhandled exception already fails closed at the gateway
    (measured: 400). The value of catching here is a *better* denial — one that carries a
    typed error and an audit record — not a more permissive one.

    It is also the LAST CHANCE to unwind the cost reservation. `_govern` clears
    `reservation` once it has either refunded (deny) or handed the charge to the RESPONSE
    interceptor (allow), so anything still in it here belongs to a request that raised
    between the ledger write and the return — a case where no `PENDING#` row exists and
    nothing downstream can reverse the charge.
    """
    deadline = _Deadline(context)
    request_id = ""
    reservation: dict = {}
    try:
        _cc = getattr(context, "client_context", None)
        request_id = str((dict(getattr(_cc, "custom", None) or {}) if _cc else {})
                         .get("REQUEST_ID", "") or "")
    except Exception:  # noqa: BLE001  # nosec B110
        # Best-effort correlation id for audit/refund only. If it cannot be read the
        # interceptor must still run and fail closed on its own terms, so this never
        # raises — request_id simply stays "".
        pass

    def _unwind(decision: str) -> None:
        """Refund a stranded reservation. Guarded, unlike the refund inside `_finish`.

        The difference is what sits above each one. `_finish` runs inside `_govern`, so a
        raise there still becomes a typed 403 here. This runs INSIDE the except branches,
        after the audit record is written, and a raise here would discard a precise
        `governance_timeout` in favour of a bare gateway 400. Denial is preserved either
        way, so the guard trades a small accounting risk for a much better error — and it
        does not weaken the invariant, because it cannot turn a deny into an allow.
        """
        if not reservation:
            return
        try:
            _refund_reservation(dict(reservation), decision)
        except Exception as exc:  # noqa: BLE001
            print(f"REFUND FAILED for {request_id} ({exc}); reservation retained")
        finally:
            reservation.clear()

    try:
        return _govern(event, context, deadline, reservation)
    except _OutOfTime as exc:
        # THE important branch. Rather than let the platform kill us — which it resolves
        # by letting the request through ungoverned — we spend our last budget saying no.
        print(f"OUT OF TIME: {exc} -> deny (fail closed)")
        _audit(request_id=request_id, decision="governance_timeout", status=403,
               control="deadline", fail_closed=True, reason=str(exc)[:300],
               remaining_ms=deadline.remaining_ms())
        _unwind("governance_timeout")
        return _closed_response(
            "governance_timeout",
            "The gateway could not complete its governance checks within the time "
            "available, so the request was refused rather than forwarded unchecked. "
            "This is a deliberate fail-closed denial; retrying is safe.",
            {"remaining_ms": deadline.remaining_ms()},
        )
    except Exception as exc:  # noqa: BLE001
        print(f"GOVERNANCE ERROR {type(exc).__name__}: {exc} -> deny (fail closed)")
        _audit(request_id=request_id, decision="governance_unavailable", status=403,
               control="unknown", fail_closed=True,
               reason=f"{type(exc).__name__}: {str(exc)[:300]}")
        _unwind("governance_unavailable")
        return _closed_response(
            "governance_unavailable",
            "The gateway could not evaluate its governance controls for this request, "
            "so the request was refused rather than forwarded unchecked. This is a "
            "deliberate fail-closed denial.",
            {"error_type": type(exc).__name__},
        )


def _replay(verdict: dict) -> dict:
    """Rebuild the response a previous attempt at this request_id already decided."""
    if verdict.get("__deny__"):
        return _closed_response(
            "governance_retry_indeterminate",
            "A previous attempt at this request did not record an outcome, so the "
            "gateway cannot tell whether it was already charged or allowed. Refused "
            "rather than risk applying its effects twice.",
            {"cause": verdict["__deny__"]},
        )
    if verdict.get("allow"):
        return _passthrough()
    return _closed_response(
        verdict.get("decision", "denied"),
        verdict.get("message", "Denied by a previous attempt at this request."),
        verdict.get("detail") or {},
        status=int(verdict.get("status", 403)),
    )


def _govern(event, context, deadline: "_Deadline", reservation: dict | None = None):
    http = event.get("http", {})
    gw_req = http.get("gatewayRequest", {}) or {}
    raw_b64 = gw_req.get("body")
    path = gw_req.get("path") or ""
    headers = gw_req.get("headers") or {}
    print(f"interceptor invoked; keys={list(event.keys())} path={path}")
    # Gateway request metadata, incl. REQUEST_ID — the only candidate correlation key
    # with the RESPONSE interceptor, whose payload carries no request data at all.
    _cc = getattr(context, "client_context", None)
    _custom = dict(getattr(_cc, "custom", None) or {}) if _cc else {}
    # Log the KEYS only — the custom dict carries SOURCE_IP, which we do not log outside
    # the (masked) audit record. REQUEST_ID is an opaque correlation id, safe to log.
    print(f"client_context_keys={sorted(_custom.keys())}")
    print(f"CORRELATION_REQUEST_ID={_custom.get('REQUEST_ID')}")

    # ---- BREAK GLASS ----------------------------------------------------
    # Checked first, and on the same cached config read everything else uses. If an
    # operator has flipped this, we want the bypass to work even if the body is
    # unparseable — that is precisely the situation someone would be breaking glass for.
    deadline.ensure("config")
    bg = _breakglass()
    if bg["enabled"]:
        print(f"BREAK GLASS ACTIVE set_by={bg['set_by']} reason={bg['reason']} "
              f"-> bypassing enforcement for path={path}")
        _audit(request_id=_custom.get("REQUEST_ID", ""), path=path,
               decision="breakglass_bypass", status=200, control="breakglass",
               fail_open=True, breakglass_set_by=bg["set_by"],
               breakglass_reason=bg["reason"],
               reason=("enforcement bypassed by an administrator via the BREAKGLASS "
                       "config row; every bypassed request is recorded"))
        return _passthrough()

    if not raw_b64:
        # FAIL CLOSED. A body-less request to an inference endpoint is not something we
        # can evaluate: no model, no prompt, no ceiling. It is also not something a
        # legitimate client sends, so denying costs nothing real.
        print("no request body -> deny (fail closed)")
        _audit(request_id=_custom.get("REQUEST_ID", ""), path=path,
               decision="no_body", status=403, control="normalize",
               guardrail_evaluated=False, fail_closed=True,
               reason="request had no body, so no control could be evaluated")
        return _closed_response(
            "no_body",
            "This request carried no body, so the gateway could not determine which "
            "model it targets or what it contains. Refused rather than forwarded.",
            {"path": path},
        )

    try:
        body = json.loads(base64.b64decode(raw_b64).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        # FAIL CLOSED. This was the most dangerous of the old fail-open paths: anyone who
        # wanted to skip governance only had to send a body we could not parse. The
        # upstream might still have understood it — a non-JSON content type, say — so
        # "we could not read it" and "it is harmless" are completely different claims.
        print(f"body decode/parse failed ({exc}) -> deny (fail closed)")
        _audit(request_id=_custom.get("REQUEST_ID", ""), path=path,
               decision="unparseable_body", status=403, control="normalize",
               guardrail_evaluated=False, fail_closed=True,
               reason=f"body decode/parse failed: {str(exc)[:200]}")
        return _closed_response(
            "unparseable_body",
            "The gateway could not parse this request body, so it could not evaluate "
            "governance on it. Refused rather than forwarded unchecked.",
            {"path": path, "parse_error": str(exc)[:200]},
        )

    # Identity and model, resolved once. Both are needed by all three controls.
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    claims = _decode_jwt_claims(auth)

    # ONE shape-agnostic read of the request. Everything below works from this bundle
    # rather than reaching into the body per control, which is what let request shape
    # decide whether governance applied.
    norm = _normalize(path, body)
    model = norm["model"]
    text_units = norm["text_units"]

    # Common audit context for every outcome below. Identity, surface and API shape are
    # recorded on ALL records so a reviewer can pivot on any of them.
    request_id = _custom.get("REQUEST_ID", "")
    audit_base = {
        "request_id": request_id,
        "source_ip": _custom.get("SOURCE_IP"),
        "username": str(claims.get("username") or claims.get("cognito:username") or ""),
        "sub": str(claims.get("sub") or ""),
        "groups": claims.get("cognito:groups") or [],
        "client_id": str(claims.get("client_id") or ""),
        "surface": norm["surface"],
        "api_shape": norm["api_shape"],
        "verb": norm["verb"] or None,
        "streaming": norm["streaming"] or None,
        "path": path,
        "model": model,
        "model_source": norm["model_source"] or None,
        "max_tokens": norm["max_output_tokens"] or None,
        "prompt_extracted": bool(text_units),
        **norm["tools"],
        **_prompt_digest(text_units),
    }

    # ---- CONTROL 0: THE MODEL MUST BE KNOWN -----------------------------
    # FAIL CLOSED. If we cannot tell which model is being invoked, we cannot evaluate
    # entitlement or price the request, so there is no basis on which to allow it.
    #
    # This is the structural fix for the bypass, not the extra regex above it. Before,
    # an unresolvable model produced an empty string, the allow/deny globs matched
    # nothing, and the request sailed through unpriced and unentitled. Denying instead
    # converts an entire CLASS of future parsing gap from a silent bypass into a loud,
    # visible failure — the next unrecognised operation breaks safely rather than open.
    if not model:
        print(f"MODEL UNRESOLVED shape={norm['api_shape']} path={path} "
              f"-> deny (fail closed)")
        _record_decision(claims, "", path, "model_unresolved", 403, "DEFAULT")
        _audit(**audit_base, decision="model_unresolved", status=403,
               control="model_entitlement", fail_closed=True,
               reason=("could not determine the target model from path or body; "
                       "denying because entitlement and pricing are both unevaluable"))
        return _block_response(
            "The gateway could not determine which model this request targets, so it "
            "cannot be authorized. This is a deliberate fail-closed denial.",
            {"api_shape": norm["api_shape"], "path": path},
        )

    # ---- CONTROL 1: MODEL ACCESS ----------------------------------------
    # Driven by the governance config table (allow/deny globs, resolved
    # USER > GROUP > DEFAULT). Native rate-limit rate:0 cannot do this job:
    # it applies to inference targets only, so it silently does nothing on the
    # runtime passthrough path.
    verdict = _model_allowed(claims, model)
    if not verdict["allowed"]:
        print(f"MODEL DENY model={model} scope={verdict['scope']} "
              f"reason={verdict['reason']}")
        _record_decision(claims, model, path, "model_access_denied", 403,
                         verdict["scope"])
        _audit(**audit_base, decision="model_access_denied", status=403,
               control="model_entitlement", scope=verdict["scope"],
               reason=verdict.get("reason"))
        return _entitlement_block(model, verdict)

    # NOTE: there is deliberately NO early return for "no text extracted" here.
    # An unrecognised body shape must not skip cost accounting, decision recording or
    # the audit trail — that would make governance depend on the request shape, which
    # is exactly the property this design claims. Only the guardrail call itself needs
    # text, and its absence is reported loudly below.

    user_sub = str(claims.get("sub") or "")

    # ---- IDEMPOTENCY -----------------------------------------------------
    # Everything above this line is a pure read and safe to repeat. Everything below
    # MUTATES state — the rate counter and the spend ledger are both `ADD` operations —
    # and the devguide warns the gateway may retry us. Claim the request id here so a
    # retry replays the first attempt's verdict instead of charging twice.
    claim = _claim_request(request_id)
    if not claim["first"]:
        return _replay(claim["verdict"] or {"__deny__": "no_verdict"})

    # Declared BEFORE _finish because _finish reads it as a closure variable and the
    # rate-limit deny path calls _finish before CONTROL 3 ever runs. Assigning it only at
    # CONTROL 3 would make that path raise "referenced before assignment" — which fails
    # closed, but would turn a clean `rate_limit_exceeded` into a generic governance error.
    _charge_state = None

    def _finish(verdict: dict, response: dict) -> dict:
        """Persist the outcome for retry replay, refund a denied reservation, and return.

        ⚠️ THE REFUND LIVES HERE ON PURPOSE. The cost reservation is taken at CONTROL 3,
        but CONTROL 4 (guardrail), the shape checks and the deadline can all deny AFTER
        it. Every one of those paths used to leave the caller charged worst-case output
        cost for a request that generated nothing — and a `cost_budget_exceeded` denial
        charged them again for being over budget, pushing them further over.

        Putting it on each deny path would guarantee the next new control forgets it.
        Every return already funnels through `_finish`, so this is the one seam where the
        refund cannot be missed.

        On the fail-closed invariant: this is NOT error handling that allows. There is no
        `except` here, so if the refund write fails the exception propagates to `handler`,
        which converts it to a typed 403 — the request is still denied. The audit record
        is written by the caller BEFORE this runs, so a refund failure cannot erase the
        reason for the denial either.
        """
        if not verdict.get("allow") and _charge_state is not None:
            _refund_reservation(_charge_state, verdict.get("decision", "denied"))
        # Settled either way: an allowed request hands the reservation to the RESPONSE
        # interceptor via the PENDING# row, and a denied one has just been refunded. What
        # remains in `reservation` after this is only ever an UNRETURNED request, which is
        # exactly what `handler` needs to reverse on the raise paths.
        if reservation is not None:
            reservation.clear()
        _record_verdict(request_id, verdict)
        return response

    # ---- CONTROL 2: RATE LIMIT (tokens + requests per window) ------------
    # The ONLY rate mechanism in this stack. The native gateway limits are deleted: they
    # attached only on recognised inference paths so the passthrough target was never
    # metered, they counted input tokens only, and they could not express a shared group
    # allowance. All three are fixed by enforcing here.
    deadline.ensure("rate")
    rate_cfg = _ratelimit_for(claims)
    if _COST_TABLE and user_sub and (rate_cfg["tokens"] > 0 or rate_cfg["requests"] > 0):
        rstate = _check_rate(user_sub, rate_cfg, _estimate_prompt_tokens(text_units))
        print(f"rate subject={rstate.get('subject')} pooled={rate_cfg['pooled']} "
              f"tokens={rstate.get('tokens')}/{rate_cfg['tokens']} "
              f"requests={rstate.get('requests')}/{rate_cfg['requests']} "
              f"scope={rate_cfg['scope']} exceeded={rstate.get('exceeded')}")
        if rstate.get("exceeded"):
            _record_decision(claims, model, path, "rate_limit_exceeded", 429,
                             rate_cfg["scope"])
            _audit(**audit_base, decision="rate_limit_exceeded", status=429,
                   control="rate_limit", scope=rate_cfg["scope"],
                   pooled=rate_cfg["pooled"],
                   rate_subject=rstate.get("subject"),
                   limit_hit=rstate.get("limit_hit"),
                   tokens_used=rstate.get("tokens"),
                   tokens_limit=rate_cfg["tokens"],
                   requests_used=rstate.get("requests"),
                   requests_limit=rate_cfg["requests"],
                   window_seconds=rate_cfg["window"])
            return _finish(
                {"allow": False, "decision": "rate_limit_exceeded", "status": 429,
                 "message": "Rate limit exceeded (replayed from a previous attempt).",
                 "detail": {"policy_scope": rate_cfg["scope"]}},
                _rate_block(rstate, rate_cfg),
            )

    # ---- CONTROL 3: COST BUDGET -----------------------------------------
    # Charged pre-dispatch on the prompt plus the declared output ceiling, against the
    # budget resolved for this principal. This is the control no native mechanism can
    # provide: token limits meter input only, so they never bound generation spend.
    deadline.ensure("charge")
    budget_cfg = _budget_for(claims)
    # NOTE: `_charge_state` is initialised near the top of _govern, above _finish, because
    # _finish closes over it. Do not re-declare it here.
    if _COST_TABLE and (budget_cfg["daily"] > 0 or budget_cfg["monthly"] > 0) and user_sub:
        state = _charge_and_check(
            user_sub, model, text_units, budget_cfg["daily"], budget_cfg["monthly"],
            max_tokens=norm["max_output_tokens"],
        )
        state["scope"] = budget_cfg["scope"]
        _charge_state = state
        # Publish it to `handler` too. The ledger has been mutated as of the line above,
        # and from here to the return, ANY raise skips _finish and writes no PENDING# row
        # — so neither this Lambda nor the response side could reverse the charge. This is
        # the handle that lets the outermost fail-closed handler settle it.
        if reservation is not None:
            reservation.clear()
            reservation.update(state)
        print(f"cost sub={user_sub[:8]} model={model} charged=${state['charged']:.5f} "
              f"day=${state['daily_total']:.5f}/{state['daily']:.5f} "
              f"month=${state['monthly_total']:.5f}/{state['monthly']:.5f} "
              f"scope={budget_cfg['scope']} exceeded={state['exceeded']}"
              f"({state['exceeded_window']})")
        if state["exceeded"]:
            win = state["exceeded_window"]
            spent = state["daily_total"] if win == "daily" else state["monthly_total"]
            cap = state["daily"] if win == "daily" else state["monthly"]
            _record_decision(claims, model, path, "cost_budget_exceeded", 429,
                             budget_cfg["scope"])
            _audit(**audit_base, decision="cost_budget_exceeded", status=429,
                   control="cost_budget", scope=budget_cfg["scope"],
                   budget_window=win,
                   spend_usd=round(spent, 6),
                   budget_usd=round(cap, 6),
                   daily_spend_usd=round(state["daily_total"], 6),
                   daily_budget_usd=round(state["daily"], 6),
                   monthly_spend_usd=round(state["monthly_total"], 6),
                   monthly_budget_usd=round(state["monthly"], 6),
                   charged_usd=round(state["charged"], 6))
            return _finish(
                {"allow": False, "decision": "cost_budget_exceeded", "status": 429,
                 "message": "Spend budget exceeded (replayed from a previous attempt).",
                 "detail": {"policy_scope": budget_cfg["scope"]}},
                _budget_block(state, model),
            )

    # ---- CONTROL 4: GUARDRAIL -------------------------------------------
    # Which guardrail (or none) is resolved per principal, so different groups can
    # be held to different content policies.
    gr = _guardrail_for(claims)
    if not gr["enabled"] or not gr["guardrail_id"]:
        # NOT a fail-open: an administrator deliberately selected "no guardrail" for this
        # scope. The absence of a content policy is the configured outcome, not a failure
        # to reach one, so it is recorded without a fail flag.
        print(f"guardrail disabled for scope={gr['scope']}; passing through")
        _record_decision(claims, model, path, "allowed_guardrail_off", 200,
                         gr["scope"])
        _audit(**audit_base, decision="allowed_guardrail_off", status=200,
               control="guardrail", scope=gr["scope"], guardrail_evaluated=False,
               guardrail_skip_reason="guardrail disabled for this scope by policy")
        return _finish({"allow": True, "decision": "allowed_guardrail_off"},
                       _passthrough())

    if not text_units:
        # THE ONE REMAINING ALLOW-WITHOUT-A-VERDICT, and it is narrowed to the case where
        # it is genuinely correct.
        #
        # "No text" has two very different causes, and the old code treated them alike:
        #
        #   (a) we UNDERSTOOD the shape and it really has no caller text — an image-only
        #       Converse turn, for instance. There is nothing for a prompt guardrail to
        #       evaluate, and denying would break a legitimate request.
        #   (b) we did NOT understand the shape, so we found no text because we did not
        #       know where to look. That is a parsing gap, and it is exactly the hole the
        #       Responses-API bypass came through.
        #
        # `_api_shape_of` already distinguishes them: a trailing `?` marks a guess and
        # "unknown" marks total non-recognition. Case (b) now fails closed.
        shape = audit_base["api_shape"]
        recognised = not (shape.endswith("?") or shape == "unknown")
        if not recognised:
            print(f"GUARDRAIL NOT EVALUATED and shape UNRECOGNISED ({shape}) "
                  f"-> deny (fail closed)")
            _record_decision(claims, model, path, "unrecognised_shape", 403, gr["scope"])
            _audit(**audit_base, decision="unrecognised_shape", status=403,
                   control="guardrail", scope=gr["scope"], guardrail_evaluated=False,
                   fail_closed=True,
                   reason=("no caller text extracted AND the request shape was not "
                           "recognised, so the absence of text cannot be trusted"))
            return _finish(
                {"allow": False, "decision": "unrecognised_shape", "status": 403,
                 "message": "Unrecognised request shape (replayed).",
                 "detail": {"api_shape": shape}},
                _closed_response(
                    "unrecognised_shape",
                    "The gateway did not recognise this request shape and could not "
                    "extract any prompt text from it, so it could not evaluate the "
                    "content policy. Refused rather than forwarded unchecked.",
                    {"api_shape": shape, "path": path},
                ),
            )
        print(f"guardrail not evaluated: recognised shape {shape} carries no caller "
              f"text (e.g. image-only); allowing and recording")
        _record_decision(claims, model, path, "allowed_no_prompt_text", 200,
                         gr["scope"])
        _audit(**audit_base, decision="allowed_no_prompt_text", status=200,
               control="guardrail", scope=gr["scope"], guardrail_evaluated=False,
               guardrail_skip_reason=("recognised shape with no caller text; nothing "
                                      "for a prompt guardrail to evaluate"))
        return _finish({"allow": True, "decision": "allowed_no_prompt_text"},
                       _passthrough())

    # FAILS CLOSED. No try/except around _apply_guardrail: if we cannot get a content
    # verdict we do not have grounds to forward the prompt. The old handler allowed on
    # error, which meant an ApplyGuardrail throttle disabled content safety for exactly
    # as long as the throttling lasted — silently, and precisely when load was highest.
    deadline.ensure("guardrail")
    result = _apply_guardrail(text_units, gr["guardrail_id"], gr["guardrail_version"])

    action = result.get("action")
    print(f"ApplyGuardrail action={action} guardrail={gr['guardrail_id']}"
          f":{gr['guardrail_version']} scope={gr['scope']}")
    if action == "GUARDRAIL_INTERVENED":
        # Summarize which assessment fired (prompt attack / content filter / PII).
        assessments = result.get("assessments", [])
        summary = []
        for a in assessments:
            if "invocationMetrics" in a:
                continue
            for key in ("contentPolicy", "sensitiveInformationPolicy", "topicPolicy", "wordPolicy"):
                if key in a:
                    summary.append(key)
        reason = "Request blocked by guardrail (input content policy)."
        _record_decision(claims, model, path, "guardrail_blocked", 403, gr["scope"])
        _audit(**audit_base, decision="guardrail_blocked", status=403,
               control="guardrail", scope=gr["scope"], guardrail_evaluated=True,
               guardrail_id=gr["guardrail_id"],
               guardrail_version=gr["guardrail_version"], guardrail_action=action,
               guardrail_policies=summary or ["guardrail"],
               model_invoked=False)
        return _finish(
            {"allow": False, "decision": "guardrail_blocked", "status": 403,
             "message": "Blocked by guardrail (replayed from a previous attempt).",
             "detail": {"assessments": summary or ["guardrail"]}},
            _block_response(reason, {"assessments": summary or ["guardrail"]}),
        )

    # Request is going to be dispatched. Park identity + the estimate under the gateway
    # REQUEST_ID so the RESPONSE interceptor can attribute output tokens and reconcile.
    decision_pk = _record_decision(claims, model, path, "allowed", 200, gr["scope"])
    # ALWAYS write the handoff row, even when no budget is configured and there is
    # therefore nothing to reconcile. It carries `decision_pk`, which is what lets the
    # RESPONSE interceptor stamp the TRUE final outcome back onto this decision record.
    #
    # That matters because this interceptor runs BEFORE Cedar. A request we allow here
    # can still be refused by the policy engine, and without the handoff the decision
    # record would keep saying `allowed / 200` for a call the caller saw fail — which is
    # exactly how the admin console came to under-count denials.
    #
    # Corollary worth knowing: a PENDING row existing means "the interceptor allowed
    # this request". Denials never write one, so the response side can tell the two
    # cases apart with no extra field.
    _pend_buckets = _cost_buckets()
    _write_pending(
        request_id=request_id,
        claims=claims,
        model=model,
        decision_pk=decision_pk,
        est_cost=(_charge_state["charged"] if _charge_state is not None else 0.0),
        day_pk=(_charge_state["day_pk"] if _charge_state is not None
                else f"{user_sub}#{_pend_buckets['day']}"),
        month_pk=(_charge_state["month_pk"] if _charge_state is not None
                  else f"{user_sub}#{_pend_buckets['month']}"),
    )
    _audit(**audit_base, decision="allowed", status=200, control="guardrail",
           scope=gr["scope"], guardrail_evaluated=True,
           guardrail_id=gr["guardrail_id"],
           guardrail_version=gr["guardrail_version"], guardrail_action=action,
           reserved_usd=(round(_charge_state["charged"], 6)
                         if _charge_state is not None else None),
           daily_spend_usd=(round(_charge_state["daily_total"], 6)
                            if _charge_state is not None else None),
           monthly_spend_usd=(round(_charge_state["monthly_total"], 6)
                              if _charge_state is not None else None),
           model_invoked=True)
    return _finish({"allow": True, "decision": "allowed"}, _passthrough())
