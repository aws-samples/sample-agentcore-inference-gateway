"""Offline test of the event-stream usage parser, before spending a deploy cycle.

Builds bodies in both real framings and asserts the parser recovers the totals.
"""
import base64
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location(
    "usage", pathlib.Path("pilot/lambda/usage/index.py"))
usage = importlib.util.module_from_spec(spec)
sys.modules["usage"] = usage
spec.loader.exec_module(usage)


def frame(payload: bytes) -> bytes:
    """Crude stand-in for AWS event-stream framing: binary prelude + headers + payload."""
    return (b"\x00\x00\x01\x2c\x00\x00\x00\x43\xef\xbe\xad\xde"
            b"\x0b:event-type\x07\x00\x05chunk" + payload + b"\xc0\xff\xee\x00")


def es_invoke_stream(in_tok, out_tok):
    """invoke-with-response-stream: chunk JSON base64-wrapped inside {"bytes": ...}."""
    body = b""
    for i in range(3):
        inner = json.dumps({"type": "content_block_delta",
                            "delta": {"text": f"chunk{i}"}}).encode()
        body += frame(json.dumps(
            {"bytes": base64.b64encode(inner).decode()}).encode())
    final_inner = json.dumps({
        "type": "message_stop",
        "amazon-bedrock-invocationMetrics": {
            "inputTokenCount": in_tok, "outputTokenCount": out_tok,
            "invocationLatency": 900, "firstByteLatency": 300},
    }).encode()
    body += frame(json.dumps(
        {"bytes": base64.b64encode(final_inner).decode()}).encode())
    return body


def es_converse_stream(in_tok, out_tok):
    """converse-stream: event JSON directly in the frame payload.

    ⚠️ `serverToolUsage:{}` is here because the REAL payload has it, and its absence is
    what let a broken parser pass this test. The original regex forbade nested braces, so
    the nested empty object made the whole response unaccountable. Copied verbatim from a
    captured live response — do not "simplify" it.
    """
    body = frame(json.dumps({"contentBlockDelta": {"delta": {"text": "hi"}}}).encode())
    body += frame(json.dumps({"metadata": {
        "metrics": {"latencyMs": 2708},
        "p": "abcdefghijklmnopqrstuvwxyz012",
        "usage": {"inputTokens": in_tok, "outputTokens": out_tok,
                  "serverToolUsage": {}, "totalTokens": in_tok + out_tok},
    }}).encode())
    return body


def sse_stream(in_tok, out_tok):
    parts = [f'data: {{"type":"message_start","message":{{"model":"m",'
             f'"usage":{{"input_tokens":{in_tok},"output_tokens":1}}}}}}',
             'data: {"type":"content_block_delta","delta":{"text":"x"}}',
             f'data: {{"type":"message_delta","usage":{{"output_tokens":{out_tok}}}}}']
    return ("\n\n".join(parts) + "\n\n").encode()


def buffered_json(in_tok, out_tok):
    return json.dumps({"model": "anthropic.claude-sonnet-5",
                       "usage": {"input_tokens": in_tok,
                                 "output_tokens": out_tok}}).encode()


def as_event(blob: bytes) -> dict:
    return {"http": {"gatewayResponse": {
        "body": base64.b64encode(blob).decode(), "statusCode": 200}}}


CASES = [
    ("buffered Anthropic JSON", buffered_json(17, 48), 17, 48),
    ("SSE (mantle streaming)", sse_stream(17, 48), 17, 48),
    ("event-stream: invoke-with-response-stream", es_invoke_stream(17, 48), 17, 48),
    ("event-stream: converse-stream", es_converse_stream(17, 48), 17, 48),
]

fails = 0
print(f"{'case':46} {'in':>5} {'out':>5}  result")
print("-" * 74)
for label, blob, want_in, want_out in CASES:
    got, model = usage._usage_from(as_event(blob))
    ok = got.get("input_tokens") == want_in and got.get("output_tokens") == want_out
    if not ok:
        fails += 1
    print(f"{label:46} {got.get('input_tokens', 0):5} {got.get('output_tokens', 0):5}  "
          f"{'PASS' if ok else f'FAIL want {want_in}/{want_out}'}")

print("\n--- prompt-cache tokens: parsed, split by TTL tier, and priced ---")
# Anthropic reports the two cache-write TTL tiers as a nested breakdown. Reading only the
# aggregate `cache_creation_input_tokens` prices 1-hour writes at the 5-minute rate, which
# under-charges them; these cases pin the split AND that the tiers use different rates.
cache_body = json.dumps({
    "model": "anthropic.claude-sonnet-5",
    "usage": {
        "input_tokens": 10, "output_tokens": 20,
        "cache_read_input_tokens": 4000,
        "cache_creation_input_tokens": 3000,
        "cache_creation": {"ephemeral_5m_input_tokens": 1000,
                           "ephemeral_1h_input_tokens": 2000},
    },
}).encode()
got, _ = usage._usage_from(as_event(cache_body))
for field, want in (("cache_read_tokens", 4000), ("cache_write_tokens", 3000),
                    ("cache_write_5m_tokens", 1000), ("cache_write_1h_tokens", 2000)):
    ok = got.get(field) == want
    if not ok:
        fails += 1
    print(f"  {field:26} -> {got.get(field)!r:>8}  "
          f"{'PASS' if ok else f'FAIL want {want}'}")

# Published Anthropic-shaped rates per 1K: read 0.1x input, 5m write 1.25x, 1h write 2.0x.
RATES = {"input": 0.003, "output": 0.015, "cache_read": 0.0003,
         "cache_write": 0.00375, "cache_write_1h": 0.006}
PRICE_CASES = [
    ("input + output only",
     {"input_tokens": 1000, "output_tokens": 1000},
     0.003 + 0.015),
    ("cache read is cheaper than input",
     {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 1000},
     0.0003),
    ("5m cache write",
     {"input_tokens": 0, "output_tokens": 0, "cache_write_5m_tokens": 1000},
     0.00375),
    ("1h cache write costs MORE than 5m",
     {"input_tokens": 0, "output_tokens": 0, "cache_write_1h_tokens": 1000},
     0.006),
    ("both tiers priced separately",
     {"input_tokens": 0, "output_tokens": 0,
      "cache_write_5m_tokens": 1000, "cache_write_1h_tokens": 1000},
     0.00375 + 0.006),
    ("all five quantities",
     {"input_tokens": 1000, "output_tokens": 1000, "cache_read_tokens": 1000,
      "cache_write_5m_tokens": 1000, "cache_write_1h_tokens": 1000},
     0.003 + 0.015 + 0.0003 + 0.00375 + 0.006),
    # Converse does not break the tiers out. The aggregate must still be charged, not
    # dropped -- a missing breakdown is not a free cache write.
    ("aggregate only -> 5m tier assumed",
     {"input_tokens": 0, "output_tokens": 0, "cache_write_tokens": 1000},
     0.00375),
]
for label, u, want in PRICE_CASES:
    got_cost = usage._price_usage(u, RATES)["cost_usd"]
    ok = abs(got_cost - want) < 1e-12
    if not ok:
        fails += 1
    print(f"  {label:38} ${got_cost:.6f}  {'PASS' if ok else f'FAIL want ${want:.6f}'}")

# With no published rates the multipliers must still charge SOMETHING, and must keep the
# tier ordering (1h > 5m > input > read). A None rate meant "free" in an earlier draft.
BARE = {"input": 0.003, "output": 0.015,
        "cache_read": None, "cache_write": None, "cache_write_1h": None}
tiers = [usage._price_usage({"cache_read_tokens": 1000}, BARE)["cost_usd"],
         usage._price_usage({"input_tokens": 1000}, BARE)["cost_usd"],
         usage._price_usage({"cache_write_5m_tokens": 1000}, BARE)["cost_usd"],
         usage._price_usage({"cache_write_1h_tokens": 1000}, BARE)["cost_usd"]]
ok = all(t > 0 for t in tiers) and tiers == sorted(tiers)
if not ok:
    fails += 1
print(f"  {'fallback multipliers stay ordered':38} "
      f"{[round(t, 6) for t in tiers]}  {'PASS' if ok else 'FAIL'}")

assumed = usage._price_usage({"cache_write_tokens": 500}, RATES)
ok = assumed["cache_write_tier_assumed"] is True
if not ok:
    fails += 1
print(f"  {'aggregate flags cache_write_tier_assumed':38} {'PASS' if ok else 'FAIL'}")

# The flag has to survive the whole path -- Converse reports an aggregate with no
# breakdown, so a real response must arrive at the pricing step already marked.
agg_body = json.dumps({"usage": {"inputTokens": 5, "outputTokens": 6,
                                 "cacheWriteInputTokens": 800}}).encode()
agg, _ = usage._usage_from(as_event(agg_body))
priced = usage._price_usage(agg, RATES)
ok = (agg.get("cache_write_5m_tokens") == 800
      and agg.get("cache_write_tier_assumed") is True
      and priced["cache_write_tier_assumed"] is True
      and abs(priced["cost_usd"] - (0.000015 + 0.00009 + 0.8 * 0.00375)) < 1e-12)
if not ok:
    fails += 1
print(f"  {'Converse aggregate: flagged end to end':38} "
      f"${priced['cost_usd']:.6f}  {'PASS' if ok else f'FAIL {agg}'}")

real = pathlib.Path("tests/fixtures_converse_stream.bin")
if real.exists():
    blob = real.read_bytes()
    got, _ = usage._usage_from(as_event(blob))
    ok = got.get("output_tokens", 0) > 0 and got.get("input_tokens", 0) > 0
    if not ok:
        fails += 1
    print(f"\n--- CAPTURED LIVE converse-stream body ({len(blob)} bytes) ---")
    print(f"  parsed -> {got}  {'PASS' if ok else 'FAIL'}")
else:
    print("\n(no captured live fixture present; synthetic cases only)")

print("\n--- negative cases (must NOT invent usage) ---")
for label, blob in (("empty body", b""),
                    ("binary garbage", bytes(range(256)) * 4),
                    ("json without usage", b'{"content":[{"text":"hi"}]}')):
    got, _ = usage._usage_from(as_event(blob))
    ok = not any(got.values())
    if not ok:
        fails += 1
    print(f"  {label:28} -> {got}  {'PASS' if ok else 'FAIL'}")

print("\n--- _body_preview shape hints ---")
for label, blob in (("event-stream invoke", es_invoke_stream(1, 2)),
                    ("converse-stream", es_converse_stream(1, 2)),
                    ("sse", sse_stream(1, 2))):
    print(f"  {label:22} {usage._body_preview(as_event(blob))}")

print(f"\n{'PASS' if fails == 0 else f'FAIL ({fails})'}")
sys.exit(1 if fails else 0)
