"""Cognito auth + gateway inference client for the pilot walkthrough.

Two small helpers the notebook imports:

    discover()                                    # point at your deployed stack first
    token = get_token("alice", config.COGNITO_DEMO_PASSWORD)   # browser-free USER_PASSWORD_AUTH
    resp  = invoke(token, "Say hello in five words.")

Plus decode_claims() to inspect the token (aud / iss / cognito:groups).

No AWS credentials needed for get_token() — Cognito InitiateAuth is an unauthenticated
public API call keyed by the app client id. invoke() is a plain HTTPS POST with the
bearer token; no AWS SDK signing involved.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass

import boto3
import requests
from botocore import UNSIGNED
from botocore.config import Config

from . import config

# Endpoints are resolved at runtime, not hardcoded. `discover()` reads them from the
# deployed CloudFormation stack outputs (the notebook calls it first); `set_endpoints()`
# overrides them manually. They start empty on purpose: baking in a specific account's
# app-client id and gateway host made the values go stale on every redeploy and tripped
# secret scanners on the token-shaped client id. Discovery is the supported path.
CLIENT_ID = ""
GATEWAY_BASE = ""


@dataclass
class Endpoints:
    region: str = config.AWS_REGION
    client_id: str = CLIENT_ID
    gateway_base: str = GATEWAY_BASE


ENDPOINTS = Endpoints()


def set_endpoints(*, client_id: str | None = None, gateway_base: str | None = None,
                  region: str | None = None) -> None:
    """Override defaults (e.g. after a fresh redeploy) without editing this file."""
    if client_id:
        ENDPOINTS.client_id = client_id
    if gateway_base:
        ENDPOINTS.gateway_base = gateway_base
    if region:
        ENDPOINTS.region = region


def discover(stack_name: str = config.STACK_NAME, region: str | None = None) -> dict:
    """Auto-discover endpoints from the deployed CloudFormation stack outputs.

    Endpoints start empty, so this (or set_endpoints) is what points the client at a
    deployment. The notebook calls it once and the client re-points itself at YOUR stack.

    Requires AWS credentials with `cloudformation:DescribeStacks` — the person who
    just ran `cdk deploy` has them. `get_token`/`invoke` still need no AWS creds;
    this is only for discovery.

    Returns the resolved values, or {} if discovery isn't possible (in which case the
    endpoints remain unset and you can call set_endpoints() manually).
    """
    region = region or ENDPOINTS.region
    try:
        cfn = boto3.client("cloudformation", region_name=region)
        outputs = {
            o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
        }
    except Exception as exc:  # noqa: BLE001
        print(f"[discover] could not read stack outputs ({type(exc).__name__}); "
              f"keeping current endpoints. Use set_endpoints() to override.")
        return {}

    resolved: dict[str, str] = {}
    client_id = outputs.get("UserPoolClientId")
    gateway_url = outputs.get("GatewayUrl")
    if client_id:
        ENDPOINTS.client_id = client_id
        resolved["client_id"] = client_id
    if gateway_url:
        ENDPOINTS.gateway_base = f"{gateway_url.rstrip('/')}/inference/v1"
        resolved["gateway_base"] = ENDPOINTS.gateway_base
    ENDPOINTS.region = region
    resolved["region"] = region
    for key in ("UserPoolId", "GuardrailId"):
        if outputs.get(key):
            resolved[key] = outputs[key]
    return resolved


def get_token(username: str, password: str) -> str:
    """Return a Cognito access token via USER_PASSWORD_AUTH (no browser)."""
    if not ENDPOINTS.client_id:
        raise RuntimeError(
            "No Cognito app client id set. Call discover() (reads it from your deployed "
            "stack) or set_endpoints(client_id=..., gateway_base=...) first."
        )
    # UNSIGNED: InitiateAuth is a public API authorized by the app client id,
    # not by AWS IAM credentials.
    client = boto3.client(
        "cognito-idp",
        region_name=ENDPOINTS.region,
        config=Config(signature_version=UNSIGNED),
    )
    resp = client.initiate_auth(
        ClientId=ENDPOINTS.client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["AccessToken"]


def decode_claims(token: str) -> dict:
    """Decode a JWT payload (no signature verification) for inspection."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def recent_spans(
    minutes: int = 15,
    limit: int = 20,
    gateway_id: str | None = None,
    region: str | None = None,
) -> list[dict]:
    """Query the gateway's OTEL spans from the `aws/spans` CloudWatch log group.

    Shows, per request, WHICH governance layer answered — the most useful
    operational signal the gateway emits:
        status  200/403/429
        layer   errorType: 'throttle' (rate limit) | 'user' (policy/authz) | None
        limit   which rate limit fired (limitKey)
        matched the dimension values that matched, e.g. 'standard,anthropic.claude-opus-5'
                (this is how you learn the real `qualifiedModelId` without guessing)

    Requires AWS credentials (CloudWatch Logs read) and CloudWatch Transaction Search
    enabled on the account. Spans take roughly 1-2 minutes to arrive.

    NOTE (verified): gateway spans do NOT contain end-user identity or token counts,
    so this cannot be used for per-user cost attribution. A wildcard rate-limit entry
    even masks its own dimension value (`matched` shows `*`, not the user's `sub`).
    Per-user usage accounting has to come from an interceptor, which does see the JWT.
    """
    import time as _time

    region = region or ENDPOINTS.region
    client = boto3.client("logs", region_name=region)
    # GOTCHA: span attribute names contain dots, so the WHOLE path goes inside
    # backticks (`attributes.http.response.status_code`). Backticking only the
    # leaf (attributes.`http.response.status_code`) silently returns nothing —
    # the column comes back empty with no error.
    filter_line = (
        f'| filter `attributes.gateway.id` = "{gateway_id}"\n' if gateway_id else ""
    )
    query = f"""
fields @timestamp,
       `attributes.http.response.status_code` as status,
       `attributes.errorType` as layer,
       `attributes.aws.agentcore.gateway.throttle.customer.limit_key` as limitKey,
       `attributes.aws.agentcore.gateway.throttle.customer.matched_entry` as matched,
       `attributes.url.path` as path
{filter_line}| sort @timestamp desc
| limit {limit}
"""

    now = int(_time.time())
    try:
        started = client.start_query(
            logGroupNames=["aws/spans"],
            startTime=now - minutes * 60,
            endTime=now,
            queryString=query,
            limit=limit,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[recent_spans] could not start query ({type(exc).__name__}). "
              f"Is CloudWatch Transaction Search enabled? {exc}")
        return []

    # Bounded poll for the async CloudWatch Logs Insights query (max 30 x 2s = 60s).
    for _ in range(30):
        _time.sleep(2)  # nosemgrep: arbitrary-sleep -- polling an async query result, bounded above
        res = client.get_query_results(queryId=started["queryId"])
        if res["status"] in ("Complete", "Failed", "Cancelled"):
            break
    if res["status"] != "Complete":
        print(f"[recent_spans] query ended with status {res['status']}")
        return []
    return [{f["field"]: f["value"] for f in row if f["field"] != "@ptr"}
            for row in res.get("results", [])]


def invoke(
    token: str,
    prompt: str,
    model: str = config.MODELS.inference_model_id,
    max_tokens: int = 64,
) -> requests.Response:
    """POST a single Anthropic Messages request through the gateway.

    Returns the raw ``requests.Response`` on purpose: the whole point of this client is
    to *demonstrate governance*, where a ``403`` (entitlement/guardrail) or ``429`` (rate
    or budget) is the desired, expected outcome the notebook inspects via ``.status_code``.
    Calling ``raise_for_status()`` here would turn those governance decisions into
    exceptions and break every demo cell, so it is deliberately omitted.
    """
    if not ENDPOINTS.gateway_base:
        raise RuntimeError(
            "No gateway base URL set. Call discover() or set_endpoints(gateway_base=...) first."
        )
    url = f"{ENDPOINTS.gateway_base}/messages"
    body = {
        "model": model,
        "anthropic_version": config.MODELS.anthropic_version,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    # Status code is the demonstrated result (see docstring); raise_for_status omitted on purpose.
    return requests.post(  # nosemgrep: use-raise-for-status
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=60,
    )


def invoke_runtime(
    token: str,
    prompt: str,
    model: str = config.MODELS.runtime_base_model,
    max_tokens: int = 64,
) -> requests.Response:
    """Send a request to the **bedrock-runtime** surface through the gateway.

    Runtime is attached as an HTTP **passthrough** target, not an inference target,
    so it is addressed differently: `<gateway>/<targetName>/model/<modelId>/invoke`
    rather than `/inference/v1/messages`. The `/inference` router does not see
    passthrough targets at all ("Model '...' not found on any target").

    Why passthrough: an inference target cannot sign for bedrock-runtime. The gateway
    derives the SigV4 service name from the endpoint hostname (`bedrock-runtime`)
    while runtime signs as `bedrock`, and the `IamCredentialProvider` override that
    fixes it is rejected on inference targets. Passthrough is permitted to set it.

    The body is identical to the Anthropic Messages format — bedrock-runtime's
    `InvokeModel` accepts it verbatim — which is what makes one governance plane over
    both surfaces practical.
    """
    base = ENDPOINTS.gateway_base.replace("/inference/v1", "")
    url = f"{base}/{config.MODELS.runtime_target_name}/model/{model}/invoke"
    body = {
        "anthropic_version": config.MODELS.anthropic_version,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    # Status code is the demonstrated result (see invoke()); raise_for_status omitted on purpose.
    return requests.post(  # nosemgrep: use-raise-for-status
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=90,
    )


def text_of(resp: requests.Response) -> str:
    """Pull the assistant text out of a successful Messages response."""
    try:
        blocks = resp.json().get("content", [])
    except Exception:  # noqa: BLE001
        return resp.text[:300]
    return "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()


def stream(
    token: str,
    prompt: str,
    model: str = config.MODELS.inference_model_id,
    max_tokens: int = 400,
    echo: bool = True,
) -> dict:
    """Stream a Messages request (SSE) through the gateway.

    Demonstrates that response STREAMING survives the guardrail REQUEST
    interceptor: the interceptor runs pre-dispatch on the request body only, so it
    never sits in the response path and nothing gets buffered.

    Returns timing/coverage stats so a notebook cell can *prove* progressive
    delivery rather than asserting it:
        {status, content_type, events, text_deltas, first_s, last_s, spread_s, text}
    A `spread_s` well above 0 means tokens arrived over time (true streaming);
    ~0 would mean the whole response landed at once (buffered).

    If the guardrail blocks the request, the gateway returns a normal JSON 403
    BEFORE any stream opens — so callers get a clean error, not a half-open stream.
    """
    url = f"{ENDPOINTS.gateway_base}/messages"
    body = {
        "model": model,
        "anthropic_version": config.MODELS.anthropic_version,
        "max_tokens": max_tokens,
        "stream": True,
        "messages": [{"role": "user", "content": prompt}],
    }
    t0 = time.time()
    # A 403 guardrail block / 429 rate or budget denial is an expected outcome the caller
    # inspects; the status check below handles non-200 without raising. raise_for_status is
    # intentionally not used here.
    resp = requests.post(  # nosemgrep: use-raise-for-status
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=120,
        stream=True,
    )
    stats = {
        "status": resp.status_code,
        "content_type": resp.headers.get("Content-Type"),
        "events": 0,
        "text_deltas": 0,
        "first_s": None,
        "last_s": None,
        "spread_s": 0.0,
        "text": "",
    }
    # Guardrail block (or any error) → plain JSON body, no stream to consume.
    if resp.status_code != 200:
        stats["text"] = resp.text[:400]
        return stats

    chunks: list[str] = []
    for line in resp.iter_lines(decode_unicode=True):
        if not line:
            continue
        stats["events"] += 1
        now = time.time() - t0
        if stats["first_s"] is None:
            stats["first_s"] = now
        stats["last_s"] = now
        if not line.startswith("data:"):
            continue
        try:  # nosec B112 - skip a malformed SSE frame; the stream continues
            evt = json.loads(line[len("data:"):].strip())
        except Exception:  # noqa: BLE001
            continue
        delta = evt.get("delta") or {}
        if delta.get("type") == "text_delta":
            stats["text_deltas"] += 1
            piece = delta.get("text", "")
            chunks.append(piece)
            if echo:
                print(piece, end="", flush=True)
    if echo and chunks:
        print()
    stats["text"] = "".join(chunks)
    if stats["first_s"] is not None and stats["last_s"] is not None:
        stats["spread_s"] = round(stats["last_s"] - stats["first_s"], 2)
    for k in ("first_s", "last_s"):
        if stats[k] is not None:
            stats[k] = round(stats[k], 2)
    return stats


if __name__ == "__main__":
    # Quick smoke test: alice (ai-platform + ml-research groups) -> a completion.
    # discover() points the client at your deployed stack (needs AWS creds for the
    # CloudFormation read only; get_token/invoke below do not).
    if not discover():
        raise SystemExit(
            "Could not discover endpoints from the stack. Deploy first, or call "
            "set_endpoints(client_id=..., gateway_base=...) manually."
        )
    tok = get_token("alice", config.COGNITO_DEMO_PASSWORD)
    claims = decode_claims(tok)
    print("aud   =", claims.get("aud"))
    print("iss   =", claims.get("iss"))
    print("groups=", claims.get("cognito:groups"))
    print("scope =", claims.get("scope"))
    r = invoke(tok, "Say hello in five words.")
    print("STATUS:", r.status_code)
    print("BODY  :", r.text[:500])
