"""RESPONSE interceptor — output-token accounting (reconciles true spend).

WHY A SECOND INTERCEPTOR
------------------------
The REQUEST interceptor can only charge for the PROMPT: output tokens do not exist yet
when it runs. Output tokens usually dominate LLM spend and are priced higher, so a
prompt-only ledger understates real cost. Only a RESPONSE interceptor sees
`usage.output_tokens`.

KNOWN TRADE-OFF (documented by AWS): for HTTP/inference targets, response interception is
**buffered** — streaming is not supported. Attaching this therefore costs token-by-token
streaming. That is a deliberate decision, not an oversight.

OPEN QUESTION THIS PROBES
-------------------------
The documented HTTP response-interceptor payload shows `gatewayRequest: null`, which would
mean no JWT and therefore **no way to attribute output tokens to a user**. This module
logs the exact event shape so that can be settled empirically before the accounting design
is fixed. It always passes the response through unchanged.
"""
import base64
import hashlib
import json
import os
import re
import time

import boto3

_REGION = os.environ.get("AWS_REGION", "us-east-1")
_COST_TABLE = os.environ.get("COST_LEDGER_TABLE", "")
# Diagnostic probe logging. OFF by default: probe output describes request/response
# structure for debugging attribution, and must never run in normal operation where it
# could surface caller metadata (e.g. source IP) or response-body content.
_PROBE = os.environ.get("PROBE_MODE", "false").lower() == "true"

# --- central governance audit log -------------------------------------------
# This function's log group is the SAME shared audit group the REQUEST interceptor
# writes to (set via the Lambda `logGroup` property), so request and response records
# for one call sit side by side and join on `request_id`.
_AUDIT_SCHEMA = "acgw.governance.audit/1"
# Response CONTENT is off by default, same posture as prompts. A response is where the
# model's generated output lands, so it can carry PII the model produced or repeated.
# The audit log group has a CloudWatch data protection policy that masks identifiers at
# ingest, which is what makes turning this on defensible.
_AUDIT_RESPONSE_TEXT = os.environ.get("AUDIT_LOG_RESPONSE_TEXT", "false").lower() == "true"
_AUDIT_RESPONSE_MAX = int(os.environ.get("AUDIT_LOG_RESPONSE_MAX_CHARS", "2000") or 2000)


def _audit(**fields) -> None:
    """Emit one RESPONSE-stage audit record. Must never raise into the response path."""
    try:
        rec = {
            "audit": True,
            "schema": _AUDIT_SCHEMA,
            "stage": "RESPONSE",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        rec.update({k: v for k, v in fields.items() if v is not None})
        print(json.dumps(rec, default=str, separators=(",", ":")))
    except Exception as exc:  # noqa: BLE001
        print(f"audit emit failed ({exc})")

try:
    _INPUT_PRICES = json.loads(os.environ.get("MODEL_PRICES_JSON", "{}"))
except Exception:  # noqa: BLE001
    _INPUT_PRICES = {}
try:
    _OUTPUT_PRICES = json.loads(os.environ.get("MODEL_OUTPUT_PRICES_JSON", "{}"))
except Exception:  # noqa: BLE001
    _OUTPUT_PRICES = {}
_DEFAULT_INPUT = 0.003
_DEFAULT_OUTPUT = 0.015
# Prompt-cache multipliers applied to the model's input price. Placeholders until the
# pricing table (which carries real cache read/write rates per model) is wired in.
# Multipliers on the input price, used ONLY when the pricing table has no published
# cache rate for a model. Verified against the live Price List API for Anthropic, where
# these happen to be exact (cache read = 0.1x input, 5-minute cache write = 1.25x).
_CACHE_READ_MULT = float(os.environ.get("CACHE_READ_MULTIPLIER", "0.1") or 0.1)
_CACHE_WRITE_MULT = float(os.environ.get("CACHE_WRITE_MULTIPLIER", "1.25") or 1.25)
# The 1-hour cache-write tier, which the pricing table carries as `cache_write_1h_per_1k`.
# Anthropic publishes it at 2.0x input. Used only when the table has no rate for the model.
_CACHE_WRITE_1H_MULT = float(os.environ.get("CACHE_WRITE_1H_MULTIPLIER", "2.0") or 2.0)

# --- real prices, refreshed daily -------------------------------------------
_PRICING_TABLE = os.environ.get("PRICING_TABLE", "")
_PRICING_TTL = int(os.environ.get("PRICING_CACHE_TTL_SECONDS", "300") or 300)
_PRICING_STALE_AFTER = int(os.environ.get("PRICING_STALE_AFTER_SECONDS", "129600") or 129600)
_rate_cache: dict = {}

_ddb = boto3.client("dynamodb", region_name=_REGION)


def _passthrough() -> dict:
    """Return the response unchanged (empty http object)."""
    return {"interceptorOutputVersion": "1.0", "http": {}}


def _describe(obj, depth: int = 0) -> str:
    """Compact structural description — keys and types, never full values."""
    if isinstance(obj, dict):
        if depth >= 2:
            return f"dict(keys={sorted(obj.keys())})"
        return "{" + ", ".join(
            f"{k}: {_describe(v, depth + 1)}" for k, v in sorted(obj.items())
        ) + "}"
    if isinstance(obj, list):
        return f"list(len={len(obj)})"
    if isinstance(obj, str):
        return f"str(len={len(obj)})"
    if obj is None:
        return "None"
    return type(obj).__name__


def _probe_log(event: dict) -> None:
    """Log everything needed to decide whether attribution is possible."""
    print(f"PROBE top_keys={sorted(event.keys())}")
    print(f"PROBE shape={_describe(event)}")

    http = event.get("http") or {}
    gw_req = http.get("gatewayRequest")
    gw_resp = http.get("gatewayResponse") or {}

    print(f"PROBE gatewayRequest_present={gw_req is not None}")
    if isinstance(gw_req, dict):
        print(f"PROBE gatewayRequest_keys={sorted(gw_req.keys())}")
        print(f"PROBE gatewayRequest_path={gw_req.get('path')}")
        hdrs = gw_req.get("headers") or {}
        # Header NAMES only — never log token values.
        print(f"PROBE request_header_names={sorted(hdrs.keys())}")
        has_auth = any(h.lower() == "authorization" for h in hdrs)
        print(f"PROBE HAS_AUTHORIZATION={has_auth}  <-- decides attribution")

    print(f"PROBE gatewayResponse_keys={sorted(gw_resp.keys())}")
    print(f"PROBE statusCode={gw_resp.get('statusCode')} "
          f"contentType={gw_resp.get('contentType')} "
          f"isStreamingResponse={gw_resp.get('isStreamingResponse')}")
    print(f"PROBE response_header_names={sorted((gw_resp.get('headers') or {}).keys())}")

    raw = gw_resp.get("body")
    if isinstance(raw, str) and raw:
        try:
            decoded = base64.b64decode(raw).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            decoded = raw
        try:
            parsed = json.loads(decoded)
            print(f"PROBE response_body_keys={sorted(parsed.keys())}")
            usage = parsed.get("usage")
            print(f"PROBE USAGE={json.dumps(usage) if usage else 'ABSENT'}")
            print(f"PROBE response_model={parsed.get('model')} id={parsed.get('id')}")
        except Exception:  # noqa: BLE001
            # Structure only — never log body content, which may echo caller/model text.
            print(f"PROBE response_body_not_json len={len(decoded)}")
    else:
        print(f"PROBE response_body={'null/absent' if not raw else type(raw).__name__}")


def _client_context_custom(context) -> dict:
    """Gateway request metadata (GATEWAY_ARN, REQUEST_ID, SOURCE_IP, ...).

    This is the ONLY plausible correlation key between the request and response
    interceptors, because the response payload carries no request data at all.
    """
    cc = getattr(context, "client_context", None)
    if cc is None:
        return {}
    return dict(getattr(cc, "custom", None) or {})


def _model_price_key(model: str) -> str:
    """Normalize a model id to the pricing table key. Must match the pricing sync."""
    if not model:
        return ""
    s = model.split("/")[-1]
    s = re.sub(r"^(us|eu|apac|ap|global)\.", "", s, flags=re.IGNORECASE)
    s = re.sub(r"^[a-z0-9]+\.", "", s, flags=re.IGNORECASE)
    s = re.sub(r"-mantle$", "", s, flags=re.IGNORECASE)
    s = re.sub(r":\d+$", "", s)
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _rates(model: str) -> dict:
    """Real per-1K rates from the pricing table, with cache read/write included.

    Replaces the `_CACHE_READ_MULT` / `_CACHE_WRITE_MULT` estimates. Those turned out to
    be accidentally correct for Anthropic (0.1x and 1.25x of input match the published
    rates exactly) but they could not express the 1-hour-TTL cache-write tier, which the
    Price List API publishes as a separate, higher rate.

    FOUR rates, not two. `cache_write_1h` was being fetched here and then dropped on the
    floor by the caller, which priced every cache write at the 5-minute rate. Any key
    returning None means "no published rate for this model" and the caller falls back to
    a multiplier on the input price -- never to zero, because a missing rate is a
    measurement gap, not a free request.
    """
    key = _model_price_key(model)
    now = time.time()
    hit = _rate_cache.get(key)
    if hit and now - hit["at"] < _PRICING_TTL:
        return hit["rates"]

    inp = out = None
    for sub, price in _INPUT_PRICES.items():
        if sub in model:
            inp = float(price)
            break
    for sub, price in _OUTPUT_PRICES.items():
        if sub in model:
            out = float(price)
            break
    rates = {
        "input": inp if inp is not None else _DEFAULT_INPUT,
        "output": out if out is not None else _DEFAULT_OUTPUT,
        "cache_read": None,     # None -> fall back to the multiplier
        "cache_write": None,
        "cache_write_1h": None,
        "source": "fallback-constants",
        "stale": False,
    }
    if _PRICING_TABLE and key:
        try:
            row = _ddb.get_item(TableName=_PRICING_TABLE,
                                Key={"model_key": {"S": key}}).get("Item")
            if row:
                def num(attr, default=None):
                    if attr not in row:
                        return default
                    try:
                        return float(row[attr]["N"])
                    except Exception:  # noqa: BLE001
                        return default
                refreshed = num("refreshed_at", 0.0) or 0.0
                rates = {
                    "input": num("input_per_1k", rates["input"]),
                    "output": num("output_per_1k", rates["output"]),
                    "cache_read": num("cache_read_per_1k"),
                    "cache_write": num("cache_write_per_1k"),
                    "cache_write_1h": num("cache_write_1h_per_1k"),
                    "source": row.get("source", {}).get("S", "price-list-api"),
                    "rate_scope": row.get("rate_scope", {}).get("S", ""),
                    "refreshed_at": int(refreshed),
                    "stale": bool(refreshed and (now - refreshed) > _PRICING_STALE_AFTER),
                }
            else:
                print(f"PRICING: no row for model_key={key!r} (model={model!r}); "
                      f"using fallback constants")
        except Exception as exc:  # noqa: BLE001
            print(f"PRICING: table read failed ({exc}); using fallback constants")

    _rate_cache[key] = {"at": now, "rates": rates}
    return rates


def _usage_from_sse(text: str) -> tuple:
    """(input_tokens, output_tokens, model) from an SSE event stream.

    WHY THIS IS NEEDED: a streaming response body is an event stream, not a JSON object,
    so there is no top-level `usage` to read. Without this, **every streaming request
    would escape output-token accounting** — its cost silently uncounted and its pending
    row left to expire. Anthropic reports usage incrementally: `message_start` carries
    `input_tokens`, and `message_delta` carries the running `output_tokens`. We take the
    input from the first and the LAST output value seen, which is the final total.
    """
    in_tok = out_tok = 0
    model = ""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if not payload or payload == "[DONE]":
            continue
        try:  # nosec B112 - skip a malformed SSE frame; parser must not crash on bad input
            evt = json.loads(payload)
        except Exception:  # noqa: BLE001
            continue
        msg = evt.get("message") or {}
        if msg:
            model = model or str(msg.get("model") or "")
            u = msg.get("usage") or {}
            in_tok = in_tok or int(u.get("input_tokens") or 0)
            if u.get("output_tokens"):
                out_tok = int(u["output_tokens"])
        u = evt.get("usage") or {}
        if u:
            if u.get("input_tokens"):
                in_tok = in_tok or int(u["input_tokens"])
            if u.get("output_tokens"):
                out_tok = int(u["output_tokens"])   # last one wins = final total
        model = model or str(evt.get("model") or "")
    return in_tok, out_tok, model


def _body_preview(event: dict, limit: int = 200) -> str:
    """A short, safe shape hint for a response we could not account.

    Diagnosing an unparseable body needs to know what it LOOKED like, but a response body
    may contain generated content, so this deliberately reports structure rather than
    text: length, the leading bytes as hex, and which framing markers are present. That
    is enough to tell SSE from event-stream from unexpected JSON without logging prose.
    """
    try:
        raw = ((event.get("http") or {}).get("gatewayResponse") or {}).get("body")
        if not isinstance(raw, str) or not raw:
            return "no body"
        blob = base64.b64decode(raw)
        markers = [name for name, probe in (
            ("sse", b"data:"),
            ("b64_payload", b'"bytes"'),
            ("invocationMetrics", b"invocationMetrics"),
            ("usage", b'"usage"'),
            ("json_open", b"{"),
        ) if probe in blob[:20000]]
        return (f"len={len(blob)} head_hex={blob[:16].hex()} "
                f"markers={','.join(markers) or 'none'}")[:limit]
    except Exception as exc:  # noqa: BLE001
        return f"preview failed: {type(exc).__name__}"


_B64_PAYLOAD = re.compile(rb'"bytes"\s*:\s*"([A-Za-z0-9+/=]{8,})"')


def _json_objects_after(raw: bytes, marker: bytes):
    """Yield each JSON object that follows `marker`, by COUNTING BRACES.

    ⚠️ THIS REPLACED A REGEX, AND THE REASON IS A REAL BUG. The first version matched
    `"usage"\\s*:\\s*(\\{[^{}]*\\})`, which forbids nested braces. The live
    `converse-stream` metadata event is:

        "usage":{"inputTokens":14,"outputTokens":17,"serverToolUsage":{},"totalTokens":31}

    `serverToolUsage:{}` is a nested object, so the regex could not match and the whole
    response went unaccounted. The synthetic test that "passed" simply omitted that field —
    it encoded the assumption instead of the payload.

    Brace counting handles arbitrary nesting, is linear, and cannot backtrack
    pathologically the way a nested-quantifier regex can. Quoted strings are tracked so a
    `}` inside a string value does not close the object early.
    """
    pos = 0
    while True:
        i = raw.find(marker, pos)
        if i < 0:
            return
        pos = i + len(marker)
        j = raw.find(b"{", pos)
        if j < 0 or j - pos > 8:          # must be the value of this key
            continue
        depth, k, in_str, esc = 0, j, False, False
        while k < len(raw) and k - j < 20000:
            c = raw[k:k + 1]
            if in_str:
                if esc:
                    esc = False
                elif c == b"\\":
                    esc = True
                elif c == b'"':
                    in_str = False
            elif c == b'"':
                in_str = True
            elif c == b"{":
                depth += 1
            elif c == b"}":
                depth -= 1
                if depth == 0:
                    yield raw[j:k + 1]
                    pos = k + 1
                    break
            k += 1
        else:
            return


def _usage_from_eventstream(raw: bytes) -> tuple:
    """(usage_dict, model) from AWS **binary event-stream** framing.

    WHY THIS EXISTS — a measured accounting bypass, not defensive coding.
    `invoke-with-response-stream` and `converse-stream` return
    `application/vnd.amazon.eventstream`, which is neither JSON nor SSE. Before this,
    those responses parsed to nothing, the reservation was RELEASED, and the request was
    served at **zero recorded spend** — so a caller who always used a streaming operation
    consumed unlimited output for free, and only their prompt counted against token rate
    limits. Verified live: `in=0 out=0` on a `200` for both operations.

    Two framings have to be handled, and the difference is why a plain text search failed:

      * `converse-stream` puts event JSON directly in the frame payload, so
        `"usage":{"inputTokens":..,"outputTokens":..}` appears in the bytes.
      * `invoke-with-response-stream` wraps each chunk as `{"bytes":"<base64>"}`, so the
        real JSON — including the final `amazon-bedrock-invocationMetrics` block carrying
        `inputTokenCount` / `outputTokenCount` — is NOT present as literal text. It has to
        be base64-decoded first.

    Works on RAW BYTES rather than a decoded str: the binary prelude and CRCs are not
    valid UTF-8, and decoding with `errors="replace"` corrupts adjacent base64 payloads.

    Takes the LAST usage/metrics block seen, because streaming reports a running total.
    """
    if not raw:
        return {}, ""

    # Every candidate JSON region: the frame bytes themselves, plus each decoded
    # base64 payload found inside them.
    regions = [raw]
    for m in _B64_PAYLOAD.finditer(raw):
        blob = m.group(1)
        try:  # nosec B112 - not every candidate blob is valid base64; skip the ones that aren't
            pad = b"=" * (-len(blob) % 4)
            regions.append(base64.b64decode(blob + pad))
        except Exception:  # noqa: BLE001
            continue

    best = {}
    model = ""
    for region in regions:
        # invocationMetrics is the authoritative total on InvokeModelWithResponseStream.
        for obj in _json_objects_after(region, b'"amazon-bedrock-invocationMetrics"'):
            try:  # nosec B112 - a candidate object may not be valid JSON; skip it, do not crash
                blk = json.loads(obj.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            best = {
                "input_tokens": int(blk.get("inputTokenCount") or 0),
                "output_tokens": int(blk.get("outputTokenCount") or 0),
                "cache_read_tokens": int(blk.get("cacheReadInputTokenCount") or 0),
                "cache_write_tokens": int(blk.get("cacheWriteInputTokenCount") or 0),
            }
        # `usage` covers converse-stream metadata and Anthropic SSE-style deltas.
        for obj in _json_objects_after(region, b'"usage"'):
            try:  # nosec B112 - a candidate object may not be valid JSON; skip it, do not crash
                blk = json.loads(obj.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            norm = _norm_usage(blk)
            if any(norm.values()):
                # Do not let a partial delta overwrite authoritative metrics.
                if not best or norm["output_tokens"] >= best.get("output_tokens", 0):
                    best = norm
        if not model:
            mm = re.search(rb'"model"\s*:\s*"([^"]{1,120})"', region)
            if mm:
                model = mm.group(1).decode("utf-8", errors="replace")
    return best, model


def _norm_usage(usage: dict) -> dict:
    """Normalize a usage block across every spelling Bedrock uses.

    THIS IS A REAL BUG FIX, not defensive coding. The Anthropic-native shape reports
    snake_case (`input_tokens`), while Bedrock **Converse** reports camelCase
    (`inputTokens`). Reading only snake_case meant every Converse response logged
    "no usage block found", the reservation was released, and the spend was never
    recorded — silent under-counting on an entire API surface.

    Cache tokens are picked up for the same reason: Converse returns
    `cacheReadInputTokens` / `cacheWriteInputTokens`, cache writes cost MORE than
    ordinary input and cache reads cost less, so ignoring them mis-prices both ways.
    """
    def pick(*names):
        for n in names:
            v = usage.get(n)
            if isinstance(v, (int, float)) and v >= 0:
                return int(v)
        return 0

    # ⚠️ CACHE WRITES HAVE TWO PRICE TIERS, and Anthropic reports them separately:
    #
    #   "cache_creation": {"ephemeral_5m_input_tokens": N, "ephemeral_1h_input_tokens": M}
    #
    # The 1-hour tier costs 1.6x the 5-minute one. Measured on the live pricing table, per
    # 1K: sonnet-4.5 writes 0.00375 (5m) vs 0.006 (1h); opus-5 0.00625 vs 0.01. Both are
    # exactly 1.25x and 2.0x the input price, which is where the fallback multipliers come
    # from. Reading only the aggregate `cache_creation_input_tokens` and pricing all of it
    # at the 5-minute rate UNDER-CHARGES any request that used 1-hour caching — and the
    # pricing table already carries `cache_write_1h_per_1k`, so the rate was being fetched
    # and then ignored. Split them so each tier is priced at its own rate, and fall back to
    # the aggregate at the 5-minute rate when the breakdown is absent (Converse does not
    # report it).
    creation = usage.get("cache_creation")
    cw_5m = cw_1h = 0
    if isinstance(creation, dict):
        def _c(*names):
            for n in names:
                v = creation.get(n)
                if isinstance(v, (int, float)) and v >= 0:
                    return int(v)
            return 0
        cw_5m = _c("ephemeral_5m_input_tokens", "ephemeral5mInputTokens")
        cw_1h = _c("ephemeral_1h_input_tokens", "ephemeral1hInputTokens")

    cw_total = pick("cache_creation_input_tokens", "cacheWriteInputTokens",
                    "cacheWriteInputTokenCount")
    assumed = False
    if not (cw_5m or cw_1h) and cw_total:
        # No breakdown available; price at the 5-minute rate and SAY SO. Without the flag
        # this assumption is indistinguishable from a measured 5-minute write, and it is
        # the one remaining path on which the cost figure can be low.
        cw_5m, assumed = cw_total, True
    return {
        "input_tokens": pick("input_tokens", "inputTokens", "prompt_tokens"),
        "output_tokens": pick("output_tokens", "outputTokens", "completion_tokens"),
        "cache_read_tokens": pick("cache_read_input_tokens", "cacheReadInputTokens",
                                  "cacheReadInputTokenCount"),
        # Kept as the total for reporting and back-compat; the two tiers below are what
        # the cost math uses.
        "cache_write_tokens": cw_total or (cw_5m + cw_1h),
        "cache_write_5m_tokens": cw_5m,
        "cache_write_1h_tokens": cw_1h,
        "cache_write_tier_assumed": assumed,
    }


def _response_facts(event: dict) -> dict:
    """What the model actually said, and what it asked to call.

    THE RESPONSE HALF OF THE AUDIT TRAIL. Until now this interceptor recorded tokens and
    cost but never content, so "what did the model reply" had no answer anywhere. That
    matters for two governance questions the request side cannot reach:

      * output-side leakage — the model repeating or generating sensitive data
      * tool USE — which tools the model actually decided to invoke, as opposed to which
        tools the caller merely made available (that half is on the REQUEST record)

    Text is hashed always and included only under AUDIT_LOG_RESPONSE_TEXT, matching the
    prompt posture. Handles every response shape: Anthropic Messages, Bedrock Converse,
    OpenAI chat, and SSE / event-stream deltas.
    """
    gw_resp = (event.get("http") or {}).get("gatewayResponse") or {}
    raw = gw_resp.get("body")
    facts: dict = {}
    if not isinstance(raw, str) or not raw:
        return facts
    try:
        text = base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return facts

    chunks: list = []
    tools_called: list = []
    stop = None

    def harvest(node, depth=0):
        """Collect assistant text and tool calls from any of the response shapes."""
        if depth > 10:
            return
        if isinstance(node, list):
            for i in node:
                harvest(i, depth + 1)
            return
        if not isinstance(node, dict):
            return
        # Tool calls: Converse `toolUse`, Anthropic `tool_use`, OpenAI `function`.
        for key in ("toolUse", "tool_use"):
            if isinstance(node.get(key), dict) and node[key].get("name"):
                tools_called.append(str(node[key]["name"]))
        if isinstance(node.get("function"), dict) and node["function"].get("name"):
            tools_called.append(str(node["function"]["name"]))
        # Assistant text. `text` covers Anthropic + Converse blocks; `content` as a bare
        # string covers OpenAI chat; `delta` covers streaming.
        t = node.get("text")
        if isinstance(t, str) and t.strip():
            chunks.append(t)
        c = node.get("content")
        if isinstance(c, str) and c.strip():
            chunks.append(c)
        for key in ("content", "output", "message", "choices", "delta", "outputs"):
            if key in node:
                harvest(node[key], depth + 1)

    try:
        body = json.loads(text)
        harvest(body)
        stop = (body.get("stop_reason") or body.get("stopReason")
                or (body.get("choices") or [{}])[0].get("finish_reason"))
    except Exception:  # noqa: BLE001
        # Streaming: SSE `data:` frames, or the binary event-stream framing that
        # converse-stream uses. Recover embedded JSON objects either way.
        for m in re.finditer(r'\{"[^\n]{0,4000}?\}', text):
            try:  # nosec B112 - regex-carved candidate may not be valid JSON; skip it
                harvest(json.loads(m.group(0)))
            except Exception:  # noqa: BLE001
                continue
        m = re.search(r'"(?:stop_reason|stopReason)"\s*:\s*"([^"]+)"', text)
        if m:
            stop = m.group(1)

    joined = "".join(chunks)
    if joined:
        facts["response_sha256"] = hashlib.sha256(joined.encode("utf-8")).hexdigest()
        facts["response_chars"] = len(joined)
        if _AUDIT_RESPONSE_TEXT:
            facts["response_text"] = joined[:_AUDIT_RESPONSE_MAX]
            facts["response_truncated"] = len(joined) > _AUDIT_RESPONSE_MAX
    if tools_called:
        facts["response_tool_calls"] = sorted(set(tools_called))
    if stop:
        facts["stop_reason"] = str(stop)
    return facts


def _usage_from(event: dict) -> tuple:
    """(usage_dict, model) from the response body.

    Handles every response shape: buffered Anthropic JSON, buffered Converse JSON, and
    an SSE event stream (streaming requests still reach this interceptor, just buffered).
    """
    gw_resp = (event.get("http") or {}).get("gatewayResponse") or {}
    raw = gw_resp.get("body")
    empty = {"input_tokens": 0, "output_tokens": 0,
             "cache_read_tokens": 0, "cache_write_tokens": 0}
    if not isinstance(raw, str) or not raw:
        return empty, ""
    try:
        blob = base64.b64decode(raw)
    except Exception:  # noqa: BLE001
        return empty, ""
    # Keep the BYTES. The event-stream parser needs them intact — its prelude and CRCs
    # are not valid UTF-8, and `errors="replace"` corrupts the base64 payloads that
    # carry the usage totals.
    text = blob.decode("utf-8", errors="replace")

    # 1. Buffered JSON — Anthropic Messages, Converse, OpenAI chat.
    try:  # nosec B110 - not JSON? fall through to the SSE / event-stream parsers below
        body = json.loads(text)
        usage = body.get("usage") or {}
        if usage:
            return _norm_usage(usage), str(body.get("model") or "")
    except Exception:  # noqa: BLE001
        pass

    # 2. SSE (`data:` frames) — mantle streaming.
    if "data:" in text:
        in_tok, out_tok, model = _usage_from_sse(text)
        if in_tok or out_tok:
            return {"input_tokens": in_tok, "output_tokens": out_tok,
                    "cache_read_tokens": 0, "cache_write_tokens": 0}, model

    # 3. AWS binary event-stream — invoke-with-response-stream, converse-stream.
    #    This branch previously did a text regex for `"usage"`, which cannot see the
    #    base64-wrapped payloads InvokeModelWithResponseStream uses, so both streaming
    #    operations went unaccounted. See _usage_from_eventstream.
    usage, model = _usage_from_eventstream(blob)
    if usage and any(usage.values()):
        return usage, model
    return empty, ""


def _stamp_outcome(request_id: str, status) -> dict:
    """Write the TRUE final outcome back onto the request's decision record.

    WHY THIS EXISTS. The REQUEST interceptor runs *before* the Cedar policy engine, so
    it records its own verdict and nothing more. When Cedar then refuses the request,
    the decision record still says `allowed / 200` while the caller received `403`.

    Measured, joining the two audit stages on request_id:

        carol  REQUEST decision=allowed status=200  ->  RESPONSE status=403   MISMATCH
        bob    REQUEST decision=model_access_denied status=403 -> 403         agrees

    The admin console reads those decision records, so every Cedar denial was being
    counted as an allowed request and the denial totals were short. This closes that
    gap at the source rather than papering over it in the UI.

    ATTRIBUTING THE DENIAL. A `PENDING#` row is written only on the allow path, so its
    presence is itself the signal:

        pending row found + final >= 400  ->  we allowed it; a LATER layer refused
        no pending row    + final >= 400  ->  the interceptor itself refused

    On this stack the only layer between the interceptor and the target that returns
    `403` is the policy engine, so that maps to `policy_engine`. Any other error status
    is upstream (target routing, Bedrock throttling, a model error) and is labelled
    `upstream` rather than guessed at.

    Best-effort: never raise into the response path. A missing stamp degrades the
    console's accuracy, it does not break inference.
    """
    out = {"stamped": False}
    if not (_COST_TABLE and request_id):
        return out
    try:
        code = int(status) if status is not None else 0
    except (TypeError, ValueError):
        code = 0

    try:
        got = _ddb.get_item(TableName=_COST_TABLE,
                            Key={"pk": {"S": f"PENDING#{request_id}"}})
        item = got.get("Item")
    except Exception as exc:  # noqa: BLE001
        print(f"outcome stamp: pending lookup failed ({exc})")
        return out

    interceptor_allowed = bool(item)
    decision_pk = (item or {}).get("decision_pk", {}).get("S", "")

    if code < 400:
        layer = "none"
    elif interceptor_allowed:
        layer = "policy_engine" if code == 403 else "upstream"
    else:
        layer = "interceptor"

    out.update({"final_status": code, "final_layer": layer,
                "interceptor_allowed": interceptor_allowed})

    # An interceptor denial needs no correction — its decision record is already right,
    # and we have no decision_pk for it anyway.
    if not decision_pk or layer in ("none", "interceptor"):
        out["stamped"] = False
        return out

    try:
        _ddb.update_item(
            TableName=_COST_TABLE,
            Key={"pk": {"S": decision_pk}},
            UpdateExpression=("SET final_status = :s, final_layer = :l, "
                              "outcome_resolved = :r"),
            ExpressionAttributeValues={
                ":s": {"N": str(code)},
                ":l": {"S": layer},
                ":r": {"BOOL": True},
            },
        )
        out["stamped"] = True
        print(f"OUTCOME CORRECTED {decision_pk}: interceptor said allowed/200, "
              f"caller received {code} from {layer}")
    except Exception as exc:  # noqa: BLE001
        print(f"outcome stamp failed ({exc}); console will show the request-stage verdict")
    return out


def _price_usage(usage: dict, r: dict) -> dict:
    """Price a normalized usage block. PURE — no I/O, so the cost math is testable.

    FIVE billable quantities, each with its own rate: input, output, cache READ, and
    cache WRITE at the 5-minute and 1-hour TTL tiers. Pricing cache writes as one line
    item under-charges every request that used 1-hour caching, and the pricing table
    already carried the 1h rate, so it was being fetched and discarded.

    Fallbacks are multipliers on the input price, never zero: an unknown rate is a
    measurement gap, and treating a gap as free is how tokens get served for nothing.
    """
    in_tok = int(usage.get("input_tokens") or 0)
    out_tok = int(usage.get("output_tokens") or 0)
    cache_r = int(usage.get("cache_read_tokens") or 0)
    cache_w = int(usage.get("cache_write_tokens") or 0)
    # `_norm_usage` splits the tiers when the provider reports them separately. When it
    # reports only an aggregate (Converse does not break the tiers out), attribute it to
    # the 5-minute bucket -- the cheaper tier, so the fallback is the one place this math
    # can still under-charge. It is recorded as `cache_write_tier_assumed` for that reason.
    cache_w_5m = int(usage.get("cache_write_5m_tokens") or 0)
    cache_w_1h = int(usage.get("cache_write_1h_tokens") or 0)
    # `_norm_usage` normally applies this fallback and flags it. Repeated here because this
    # function must be correct for ANY usage dict handed to it, including one assembled by a
    # caller that never went through `_norm_usage` -- pricing a cache write at zero is the
    # one outcome that is never acceptable.
    assumed = bool(usage.get("cache_write_tier_assumed"))
    if not (cache_w_5m or cache_w_1h) and cache_w:
        cache_w_5m, assumed = cache_w, True

    in_price, out_price = r["input"], r["output"]
    # Real published cache rates when the table has them; the multiplier estimates only
    # if it does not. Ignoring cache tokens entirely (the original behaviour) understated
    # cache reads and overstated nothing — but cache WRITES cost more than plain input,
    # so the error ran both ways.
    cr_price = r["cache_read"] if r.get("cache_read") is not None \
        else in_price * _CACHE_READ_MULT
    cw_price = r["cache_write"] if r.get("cache_write") is not None \
        else in_price * _CACHE_WRITE_MULT
    # The 1-hour tier costs more than the 5-minute one (Anthropic: 2.0x input vs 1.25x).
    # Its fallback is its own multiplier, not the 5m rate, because a 1h write is never
    # cheaper and guessing low here is precisely the bug being fixed.
    cw1h_price = r["cache_write_1h"] if r.get("cache_write_1h") is not None \
        else in_price * _CACHE_WRITE_1H_MULT
    cost = (
        (in_tok / 1000.0) * in_price
        + (out_tok / 1000.0) * out_price
        + (cache_r / 1000.0) * cr_price
        + (cache_w_5m / 1000.0) * cw_price
        + (cache_w_1h / 1000.0) * cw1h_price
    )
    return {
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "cache_read_tokens": cache_r,
        "cache_write_tokens": cache_w or (cache_w_5m + cache_w_1h),
        "cache_write_5m_tokens": cache_w_5m,
        "cache_write_1h_tokens": cache_w_1h,
        "cache_write_tier_assumed": assumed,
        "cost_usd": cost,
    }


def _reconcile(request_id: str, usage: dict, resp_model: str) -> dict:
    """Replace the request-time ESTIMATE with true cost (input + output + cache).

    The request interceptor charged an estimate from the prompt only (it cannot know
    output tokens). Here we know both, so we apply the DIFFERENCE to the same window
    bucket — an adjustment, not a second charge, so nothing is double-counted.

    This is the AUTHORITATIVE cost point. The reservation is deliberately a coarse upper
    bound (no cache pricing, worst-case output); every correction lands here.
    """
    pend_key = {"pk": {"S": f"PENDING#{request_id}"}}
    try:
        got = _ddb.get_item(TableName=_COST_TABLE, Key=pend_key)
        item = got.get("Item")
    except Exception as exc:  # noqa: BLE001
        print(f"pending lookup failed ({exc}); cannot attribute this response")
        return {"attributed": False, "reason": f"pending lookup failed: {str(exc)[:200]}"}
    if not item:
        # No pending row: the request was blocked before dispatch, or the row expired.
        print(f"no pending row for REQUEST_ID={request_id}; nothing to reconcile")
        return {"attributed": False, "reason": "no pending row for this request id"}

    sub = item.get("sub", {}).get("S", "")
    model = item.get("model", {}).get("S", "") or resp_model
    bucket = item.get("bucket", {}).get("N", "0")
    est = float(item.get("est_cost", {}).get("N", "0"))
    decision_pk = item.get("decision_pk", {}).get("S", "")
    username = item.get("username", {}).get("S", "?")

    r = _rates(model)
    priced = _price_usage(usage, r)
    in_tok = priced["input_tokens"]
    out_tok = priced["output_tokens"]
    cache_r = priced["cache_read_tokens"]
    cache_w = priced["cache_write_tokens"]
    cache_w_5m = priced["cache_write_5m_tokens"]
    cache_w_1h = priced["cache_write_1h_tokens"]
    true_cost = priced["cost_usd"]
    delta = true_cost - est

    try:
        resp = _ddb.update_item(
            TableName=_COST_TABLE,
            Key={"pk": {"S": f"{sub}#{bucket}"}},
            UpdateExpression="ADD spend :d",
            ExpressionAttributeValues={":d": {"N": str(delta)}},
            ReturnValues="UPDATED_NEW",
        )
        total = float(resp["Attributes"]["spend"]["N"])
    except Exception as exc:  # noqa: BLE001
        print(f"reconcile failed ({exc})")
        return {"attributed": False, "reason": f"ledger update failed: {str(exc)[:200]}"}

    print(f"RECONCILE user={username} model={model} in={in_tok} out={out_tok} "
          f"cache_r={cache_r} cache_w={cache_w} "
          f"(5m={cache_w_5m} 1h={cache_w_1h}) "
          f"est=${est:.6f} true=${true_cost:.6f} delta=${delta:+.6f} "
          f"window_total=${total:.6f}")
    outcome = {
        "attributed": True,
        "username": username,
        "sub": sub,
        "model": model,
        # Provenance of the rates used, so any cost figure in the audit log can be
        # traced to the prices it was computed from.
        "price_source": r.get("source"),
        "price_rate_scope": r.get("rate_scope") or None,
        "price_refreshed_at": r.get("refreshed_at") or None,
        "price_stale": True if r.get("stale") else None,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "cache_read_tokens": cache_r or None,
        "cache_write_tokens": cache_w or None,
        # Both tiers are recorded because they are priced differently, so a cost figure
        # cannot be re-derived from the aggregate alone.
        "cache_write_5m_tokens": cache_w_5m or None,
        "cache_write_1h_tokens": cache_w_1h or None,
        # True when the provider gave only an aggregate and we assumed the 5-minute tier.
        # The one remaining way this figure can be low, so it is on the record.
        "cache_write_tier_assumed": True if priced["cache_write_tier_assumed"] else None,
        "reserved_usd": round(est, 6),
        "cost_usd": round(true_cost, 6),
        "adjustment_usd": round(delta, 6),
        "window_spend_usd": round(total, 6),
    }

    # Enrich the decision row so the console can show real usage per request.
    if decision_pk:
        try:
            _ddb.update_item(
                TableName=_COST_TABLE,
                Key={"pk": {"S": decision_pk}},
                UpdateExpression=("SET input_tokens = :i, output_tokens = :o, "
                                  "cost_usd = :c, est_cost_usd = :e"),
                ExpressionAttributeValues={
                    ":i": {"N": str(in_tok)},
                    ":o": {"N": str(out_tok)},
                    ":c": {"N": str(true_cost)},
                    ":e": {"N": str(est)},
                },
            )
        except Exception as exc:  # noqa: BLE001
            print(f"decision enrich failed ({exc})")

    try:
        _ddb.delete_item(TableName=_COST_TABLE, Key=pend_key)
    except Exception as exc:  # noqa: BLE001
        print(f"pending cleanup failed ({exc})")

    return outcome


def _settle_reservation(request_id: str, refund: bool) -> dict:
    """Close out the `PENDING#` handoff row, refunding the reservation or keeping it.

    The request interceptor reserved `max_tokens` worth of output cost up front. What
    happens when actual usage cannot be read depends entirely on whether the request
    SUCCEEDED, and conflating the two cases was a real accounting bypass:

        refund=True   the request failed, so no output was produced. Holding the charge
                      would bill for generation that never happened.
        refund=False  the request returned 2xx, so output WAS delivered and we simply
                      could not measure it. Refunding here charges nothing for real
                      generation — which is how streaming operations went unaccounted.

    Either way the handoff row is deleted rather than left to its TTL, so leftover
    `PENDING#` rows always mean "in flight" and never "already settled".
    """
    key = {"pk": {"S": f"PENDING#{request_id}"}}
    out = {"settled": False, "refunded": False, "retained_usd": 0.0}
    try:
        got = _ddb.get_item(TableName=_COST_TABLE, Key=key)
        item = got.get("Item")
        if not item:
            return out
        sub = item.get("sub", {}).get("S", "")
        bucket = item.get("bucket", {}).get("N", "0")
        est = float(item.get("est_cost", {}).get("N", "0"))
        if refund and sub and est:
            _ddb.update_item(
                TableName=_COST_TABLE,
                Key={"pk": {"S": f"{sub}#{bucket}"}},
                UpdateExpression="ADD spend :d",
                ExpressionAttributeValues={":d": {"N": str(-est)}},
            )
            # Say REFUNDED, not "released". The old wording is what made the wrong branch
            # look correct in the logs for as long as it did.
            print(f"REFUNDED reservation of {est:.6f} to {sub[:8]} "
                  f"(request failed; no output produced)")
            out["refunded"] = True
        elif not refund:
            # Nothing to write: the reservation is already in the spend counter from the
            # request side. Retaining it is simply declining to reverse it.
            print(f"RETAINED reservation of {est:.6f} for {sub[:8]} "
                  f"(unmeasurable success; recorded spend is an upper bound)")
            out["retained_usd"] = round(est, 6)
        _ddb.delete_item(TableName=_COST_TABLE, Key=key)
        out["settled"] = True
        return out
    except Exception as exc:  # noqa: BLE001
        print(f"reservation settle failed ({exc})")
        return out


def handler(event, context):
    custom = _client_context_custom(context)
    request_id = custom.get("REQUEST_ID", "")
    try:
        if _PROBE:
            # Log the KEYS present, not the values — the custom dict carries SOURCE_IP.
            print(f"PROBE client_context_keys={sorted(custom.keys())}")
            print(f"PROBE CORRELATION_REQUEST_ID={request_id}")
            _probe_log(event)
    except Exception as exc:  # noqa: BLE001
        print(f"probe logging failed ({exc})")

    gw_resp = (event.get("http") or {}).get("gatewayResponse") or {}
    status = gw_resp.get("statusCode")
    streaming = gw_resp.get("isStreamingResponse")
    content_type = gw_resp.get("contentType")
    body_present = bool(gw_resp.get("body"))

    # What the model said and which tools it called. Computed once and attached to
    # whichever audit record this invocation ends up emitting.
    try:
        rfacts = _response_facts(event)
    except Exception as exc:  # noqa: BLE001
        print(f"response fact extraction failed ({exc})")
        rfacts = {}

    # Resolve the TRUE final outcome first, before any of the accounting branches. This
    # is the only place in the system that can see both what the interceptor decided and
    # what the caller actually received, so it is the only place a Cedar denial can be
    # attributed. Runs on every response, including errors.
    try:
        resolved = _stamp_outcome(request_id, status)
    except Exception as exc:  # noqa: BLE001
        print(f"outcome resolution failed ({exc})")
        resolved = {}
    rfacts.update({k: v for k, v in resolved.items() if k != "stamped"})

    try:
        if status and int(status) >= 400:
            # REFUND. The request failed, so no output was generated and the reservation
            # must be reversed. This branch previously did nothing, which left the caller
            # charged worst-case output cost for a request that produced nothing — and it
            # is the ONLY place that can fix the denials the request interceptor cannot
            # see, because Cedar and upstream errors both happen after that Lambda has
            # already returned. A `PENDING#` row exists precisely when the interceptor
            # allowed the request, which is exactly the case where a later layer denied it.
            settle = _settle_reservation(request_id, refund=True)
            print(f"response status {status}; no usage to account; "
                  f"refunded={settle.get('refunded')}")
            _audit(request_id=request_id, status=status, content_type=content_type,
                   upstream_error=True, accounted=False, **rfacts,
                   **{f"settle_{k}": v for k, v in settle.items()},
                   reason=("request was refused by "
                           f"{resolved.get('final_layer', 'an unknown layer')}; "
                           "no usage to account; reservation refunded"))
        elif not _COST_TABLE or not request_id:
            print("no ledger table or REQUEST_ID; skipping accounting")
            _audit(request_id=request_id, status=status, content_type=content_type,
                   accounted=False, **rfacts,
                   reason="no ledger table or no REQUEST_ID; cannot attribute")
        else:
            usage, model = _usage_from(event)
            if any(usage.values()):
                outcome = _reconcile(request_id, usage, model) or {}
                _audit(request_id=request_id, status=status,
                       content_type=content_type,
                       response_streaming=streaming,
                       response_body_present=body_present,
                       accounted=bool(outcome.get("attributed")), **rfacts,
                       **{k: v for k, v in outcome.items() if k != "attributed"})
            else:
                # ⚠️ RETAIN, DO NOT RELEASE. This branch used to release the reservation,
                # reasoning that the caller should not be charged for worst-case output
                # they may never have received. That reasoning is correct for a FAILED
                # request and wrong for this one: we are inside a 2xx, so the model ran
                # and output WAS delivered. Releasing it charged nothing for real
                # generation, which is precisely how streaming operations escaped cost
                # accounting entirely — measured at zero recorded spend on
                # invoke-with-response-stream and converse-stream.
                #
                # So the rule is: unmeasurable FAILURE refunds, unmeasurable SUCCESS keeps
                # the worst-case charge. The reservation was computed from the caller's own
                # declared output ceiling, so retaining it over-charges at worst and never
                # under-charges — the safe direction for a spend control.
                #
                # Still alert-worthy: the ledger is now an upper bound rather than a
                # measurement for this request, and `usage_estimated` marks exactly which
                # rows those are so a reader can tell measured spend from bounded spend.
                print("UNACCOUNTED: no parseable usage on a successful response; "
                      "RETAINING the worst-case reservation (upper bound)")
                _audit(request_id=request_id, status=status,
                       content_type=content_type,
                       response_streaming=streaming,
                       response_body_present=body_present,
                       accounted=False, unaccounted_success=True, **rfacts,
                       **{f"settle_{k}": v for k, v in
                          _settle_reservation(request_id, refund=False).items()},
                       usage_estimated=True,
                       body_preview=_body_preview(event),
                       reason=("no parseable usage block on a SUCCESSFUL response; "
                               "worst-case reservation retained, so recorded spend for "
                               "this request is an upper bound, not a measurement"))
    except Exception as exc:  # noqa: BLE001
        # Accounting must never break the caller's response.
        print(f"accounting error ({exc}); passing response through")
        _audit(request_id=request_id, status=status, accounted=False,
               error=str(exc)[:300],
               reason="accounting raised; response passed through unchanged")

    return _passthrough()
