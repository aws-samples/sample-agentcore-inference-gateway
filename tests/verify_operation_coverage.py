"""Coverage matrix: is EVERY endpoint surface x API operation actually governed?

The thesis is that one gateway governs any inference call regardless of backend and
regardless of operation. This tests that claim rather than assuming it, and separates two
things that are easy to conflate:

  GOVERNED = the interceptor evaluated it and wrote a DECISION# record
  SERVED   = the target actually dispatched it to a model

An operation can be governed and not served (the provider target declares only the
Anthropic Messages operation), which is fine. What would NOT be fine is served and not
governed -- that is a bypass.

For each surface/operation it drives an entitled user (alice) and an unentitled one
(bob -> opus, which every surface must refuse).
"""
import json
import sys
import time
from collections import defaultdict

import boto3
import requests

sys.path.insert(0, ".")
from pilot import config, inference_client as ic  # noqa: E402

ddb = boto3.client("dynamodb", region_name="us-east-1")
LEDGER = "acgw-pilot-cost-ledger"
PROMPT = "Explain what a load balancer does."

ic.discover()
BASE = ic.ENDPOINTS.gateway_base                     # .../inference/v1
ROOT = BASE.replace("/inference/v1", "")
RT = config.MODELS.runtime_target_name

SONNET_PROV = "bedrockprov/anthropic.claude-sonnet-5"
SONNET_CONN = "bedrock/anthropic.claude-sonnet-5"
OPUS_PROV = "bedrockprov/anthropic.claude-opus-5"
OPUS_CONN = "bedrock/anthropic.claude-opus-5"
RT_SONNET = "us.anthropic.claude-sonnet-5"
RT_OPUS = "us.anthropic.claude-opus-5"


def messages_body(model, mx=48):
    return {"model": model, "anthropic_version": config.MODELS.anthropic_version,
            "max_tokens": mx, "messages": [{"role": "user", "content": PROMPT}]}


def chat_body(model, mx=48):
    return {"model": model, "max_tokens": mx,
            "messages": [{"role": "user", "content": PROMPT}]}


def responses_body(model, mx=48):
    return {"model": model, "max_output_tokens": mx, "input": PROMPT}


def converse_body(mx=48):
    return {"messages": [{"role": "user", "content": [{"text": PROMPT}]}],
            "inferenceConfig": {"maxTokens": mx}}


def rt_messages_body(mx=48):
    return {"anthropic_version": config.MODELS.anthropic_version,
            "max_tokens": mx, "messages": [{"role": "user", "content": PROMPT}]}


# (label, url, body-factory for allowed-user, body/model for denied-user)
CASES = [
    ("mantle-provider  /v1/messages", f"{BASE}/messages",
     messages_body(SONNET_PROV), messages_body(OPUS_PROV)),
    ("mantle-connector /v1/messages", f"{BASE}/messages",
     messages_body(SONNET_CONN), messages_body(OPUS_CONN)),
    ("mantle-provider  /v1/chat/completions", f"{BASE}/chat/completions",
     chat_body(SONNET_PROV), chat_body(OPUS_PROV)),
    ("mantle-provider  /v1/responses", f"{BASE}/responses",
     responses_body(SONNET_PROV), responses_body(OPUS_PROV)),
    ("runtime-passthru /invoke", f"{ROOT}/{RT}/model/{RT_SONNET}/invoke",
     rt_messages_body(), None),
    ("runtime-passthru /invoke-with-response-stream",
     f"{ROOT}/{RT}/model/{RT_SONNET}/invoke-with-response-stream",
     rt_messages_body(), None),
    ("runtime-passthru /converse", f"{ROOT}/{RT}/model/{RT_SONNET}/converse",
     converse_body(), None),
    ("runtime-passthru /converse-stream",
     f"{ROOT}/{RT}/model/{RT_SONNET}/converse-stream",
     converse_body(), None),
]

# denied-user variants for the passthrough put the model in the PATH
RT_DENY = {
    "runtime-passthru /invoke": f"{ROOT}/{RT}/model/{RT_OPUS}/invoke",
    "runtime-passthru /invoke-with-response-stream":
        f"{ROOT}/{RT}/model/{RT_OPUS}/invoke-with-response-stream",
    "runtime-passthru /converse": f"{ROOT}/{RT}/model/{RT_OPUS}/converse",
    "runtime-passthru /converse-stream":
        f"{ROOT}/{RT}/model/{RT_OPUS}/converse-stream",
}

toks = {u: ic.get_token(u, config.COGNITO_DEMO_PASSWORD) for u in ("alice", "bob")}


def post(user, url, body):
    try:
        r = requests.post(url, headers={"Authorization": f"Bearer {toks[user]}",
                                        "Content-Type": "application/json"},
                          data=json.dumps(body), timeout=90)
        why = ""
        if r.status_code != 200:
            try:
                j = r.json()
                why = (j.get("error", {}) or {}).get("type") or str(j)[:44]
            except Exception:
                why = r.text[:44]
        return r.status_code, why
    except Exception as e:  # noqa: BLE001
        return "EXC", type(e).__name__


t0 = int(time.time()) - 5
rows = []
print(f"{'surface / operation':46} {'alice':22} {'bob->opus':22}")
print("-" * 94)
for label, url, abody, bbody in CASES:
    a = post("alice", url, abody)
    time.sleep(1)
    if bbody is not None:
        b = post("bob", url, bbody)
    else:
        b = post("bob", RT_DENY[label], abody)
    time.sleep(1)
    rows.append((label, a, b))
    print(f"{label:46} {str(a[0]) + ' ' + a[1][:16]:22} "
          f"{str(b[0]) + ' ' + b[1][:16]:22}")

print("\nwaiting for decision records...")
time.sleep(20)

items, kw = [], {"TableName": LEDGER}
while True:
    p = ddb.scan(**kw)
    items += p.get("Items", [])
    if "LastEvaluatedKey" not in p:
        break
    kw["ExclusiveStartKey"] = p["LastEvaluatedKey"]

by_path = defaultdict(list)
for it in items:
    if not it.get("pk", {}).get("S", "").startswith("DECISION#"):
        continue
    ts = int(float(it.get("ts", {}).get("N", 0)))
    if ts < t0:
        continue
    by_path[it.get("path", {}).get("S", "?")].append({
        "user": it.get("username", {}).get("S"),
        "decision": it.get("decision", {}).get("S"),
        "status": int(float(it.get("status", {}).get("N", 0))),
        "in": int(float(it.get("input_tokens", {}).get("N", 0))),
        "out": int(float(it.get("output_tokens", {}).get("N", 0))),
        "model": it.get("model", {}).get("S"),
    })

print("\n" + "=" * 94)
print("GOVERNED? — decision records written during this run, grouped by request path")
print("=" * 94)
for path in sorted(by_path):
    recs = by_path[path]
    accounted = sum(1 for r in recs if r["out"] > 0)
    print(f"\n  path {path}   ({len(recs)} records, {accounted} with output tokens)")
    for r in recs:
        print(f"     {r['user']:6} {r['decision']:22} status={r['status']:4} "
              f"in={r['in']:5} out={r['out']:5} {r['model']}")

print("\n" + "=" * 94)
print("VERDICT")
print("=" * 94)
print(f"{'surface / operation':46} {'served?':10} {'governed?':11} denial enforced?")
print("-" * 94)
for label, a, b in rows:
    served = "YES" if a[0] == 200 else f"no({a[0]})"
    gov = "?"
    for path, recs in by_path.items():
        if any(r["user"] == "alice" for r in recs) and (
                path.split("/")[-1] in label or path in label):
            gov = "YES"
    denied = "YES" if b[0] in (403,) else f"no({b[0]})"
    print(f"{label:46} {served:10} {gov:11} {denied}")
print("\nA row that is SERVED but not GOVERNED is a bypass. Anything not served is fine.")
