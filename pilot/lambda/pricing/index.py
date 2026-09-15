"""Pricing sync — keeps real Bedrock token rates in DynamoDB, refreshed on a schedule.

WHY THIS EXISTS
---------------
Cost governance built on hardcoded prices is wrong the moment AWS changes a rate, and
"wrong" here means either letting spend through or blocking legitimate traffic. The
interceptors therefore price requests from a table that this Lambda refreshes daily from
the **AWS Price List API**.

THE THING THAT MAKES THIS NON-OBVIOUS: TWO SERVICE CODES
--------------------------------------------------------
Bedrock pricing is split across two Price List service codes with *different schemas*,
and querying only the first misses every current-generation Anthropic model:

1. ``AmazonBedrock`` — Nova, Titan, Llama, Mistral, DeepSeek, and LEGACY Claude
   (2.x, 3 Sonnet, 3 Haiku, Instant). Has an ``inferenceType`` attribute. Priced per
   **1K tokens**. Usagetypes like ``USE1-NovaPro-cache-read-input-token-count``.

2. ``AmazonBedrockFoundationModels`` — marketplace-style listings covering CURRENT
   Claude (Sonnet / Opus / Haiku 4.x and 5.x), Cohere, Jamba and others. No
   ``inferenceType``; the model is identified by ``servicename``, e.g.
   "Claude Opus 5 (Amazon Bedrock Edition)". Priced per **1M tokens**.

Mixing the units without normalizing would misprice by 1000x. Source 2 wins when both
match, because it carries the current generations and publishes explicit cache rates
including the 1-hour TTL tier.

TWO USAGETYPE FORMS IN SOURCE 2 (verified live, 2026-09)
--------------------------------------------------------
Source 2 is mid-migration between naming conventions and BOTH are in use:

    old  USE1-MP:USE1_OutputTokenCount_Global-Units
    new  USE1-MP:USE1_cache_read_tokens_global_standard-Units

`claude-opus-5` and `claude-sonnet-5` — the models this pilot actually serves — use the
NEW form. Handling only the old CamelCase form silently yields no price for them, which
is exactly the failure this table is meant to prevent. Both forms are parsed below.

REGIONAL VS GLOBAL RATES
------------------------
Source 2 publishes two rate scopes, roughly 10% apart. A bare model id
(`anthropic.claude-opus-5`) is regional; a cross-region inference profile
(`us.anthropic.claude-opus-5`) is global. `RATE_SCOPE` selects the preference and
defaults to `global`, because the runtime surface here uses `us.*` profiles.

A DELIBERATE DIFFERENCE FROM THE REFERENCE IMPLEMENTATION
---------------------------------------------------------
Solutions that meter Bedrock via **model invocation logging** must skip `-mantle-`
usagetypes, because mantle traffic does not appear in those logs. This pilot meters at
the **gateway interceptor**, so it sees mantle requests directly and those rates are
both usable and necessary. They are ingested here.
"""
import json
import os
import re
import time
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError

_REGION = os.environ.get("AWS_REGION", "us-east-1")
_TABLE = os.environ["PRICING_TABLE"]
# Price List API is only served from us-east-1 and ap-south-1.
_PRICING_REGION = "us-east-1"
_RATE_SCOPE = (os.environ.get("RATE_SCOPE") or "global").strip().lower()
if _RATE_SCOPE not in ("global", "regional"):
    _RATE_SCOPE = "global"

_LEGACY_CODE = "AmazonBedrock"
_FM_CODE = "AmazonBedrockFoundationModels"

_ddb = boto3.client("dynamodb", region_name=_REGION)
_pricing = boto3.client("pricing", region_name=_PRICING_REGION)

_REGION_TO_LOCATION = {
    "us-east-1": "US East (N. Virginia)", "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)", "us-west-2": "US West (Oregon)",
    "eu-west-1": "EU (Ireland)", "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)", "eu-central-1": "EU (Frankfurt)",
    "eu-north-1": "EU (Stockholm)", "eu-south-1": "EU (Milan)",
    "ap-northeast-1": "Asia Pacific (Tokyo)", "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-southeast-1": "Asia Pacific (Singapore)", "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-south-1": "Asia Pacific (Mumbai)", "sa-east-1": "South America (Sao Paulo)",
    "ca-central-1": "Canada (Central)", "il-central-1": "Israel (Tel Aviv)",
}

# ---- source 1 (AmazonBedrock) ----------------------------------------------
_LEGACY_COMPONENTS = {
    "Input tokens": "input",
    "Output tokens": "output",
    "Prompt cache read input tokens": "cache_read",
    "Prompt cache write input tokens": "cache_write",
}
# Suffix patterns stripped to derive a model key. Cache suffixes contain the word
# "input", so they MUST be tried before the plain input/output patterns.
_LEGACY_SUFFIXES = [
    r"-cache-read-input-token-count$", r"-cache-write-input-token-count$",
    r"-cache-read-tokens(-\w+)?$", r"-cache-write-tokens(-\w+)?$",
    r"-(input|output)-tokens(-\w+)?$", r"-(input|output)-token-count$",
]

# ---- source 2 (AmazonBedrockFoundationModels), OLD CamelCase form -----------
# Longest-first: CacheWrite1h... shares a prefix with CacheWrite...
_FM_OLD = re.compile(
    r"MP:[A-Za-z0-9]+_"
    r"(?P<component>CacheWrite1hInputTokenCount|CacheWriteInputTokenCount"
    r"|CacheReadInputTokenCount|InputTokenCount|OutputTokenCount)"
    r"(?P<scope>_Global)?(?P<batch>_Batch)?-Units$"
)
_FM_OLD_COMPONENTS = {
    "InputTokenCount": "input", "OutputTokenCount": "output",
    "CacheReadInputTokenCount": "cache_read",
    "CacheWriteInputTokenCount": "cache_write",
    "CacheWrite1hInputTokenCount": "cache_write_1h",
}

# ---- source 2, NEW snake_case form (what claude-*-5 uses) ------------------
#   MP:USE1_input_tokens_standard-Units
#   MP:USE1_cache_read_tokens_global_standard-Units
#   MP:USE1_cache_write_tokens_1h_global_standard-Units
_FM_NEW = re.compile(
    r"MP:[A-Za-z0-9]+_"
    r"(?P<component>input|output|cache_read|cache_write)_tokens"
    r"(?P<ttl>_1h)?"
    r"(?P<scope>_global)?"
    r"(?:_(?P<tier>standard|flex|priority|batch))?"
    r"-Units$"
)


def _location() -> str:
    return _REGION_TO_LOCATION.get(_REGION, "US East (N. Virginia)")


def _fetch(service_code: str, filters: list) -> list:
    """Page through GetProducts, tolerating a failure of either source."""
    records, token = [], None
    while True:
        kwargs = {"ServiceCode": service_code, "Filters": filters,
                  "MaxResults": 100, "FormatVersion": "aws_v1"}
        if token:
            kwargs["NextToken"] = token
        try:
            resp = _pricing.get_products(**kwargs)
        except ClientError as exc:
            print(f"get_products failed for {service_code}: {exc}")
            break
        for row in resp.get("PriceList", []):
            records.append(json.loads(row) if isinstance(row, str) else row)
        token = resp.get("NextToken")
        if not token:
            break
    return records


def _price_and_unit(on_demand: dict):
    """First USD rate and its unit. Zero is returned, not skipped — some rates are
    legitimately $0.00 (Nova charges nothing for cache writes) and treating that as
    missing would substitute a non-zero estimate."""
    for term in on_demand.values():
        for dim in term.get("priceDimensions", {}).values():
            usd = dim.get("pricePerUnit", {}).get("USD")
            if usd is not None:
                return Decimal(usd), dim.get("unit", "")
    return None, ""


def _per_1k(price: Decimal, unit: str) -> Decimal:
    u = (unit or "").lower()
    if "1m" in u or "million" in u:
        return price / Decimal(1000)
    if "1k" in u or "thousand" in u:
        return price
    print(f"unrecognized unit {unit!r}; assuming per-1K")
    return price


def _model_key(name: str) -> str:
    """Normalize a model id OR a Price List servicename to one comparable key.

        anthropic.claude-opus-5                     -> claudeopus5
        us.anthropic.claude-opus-5                  -> claudeopus5
        bedrockprov/anthropic.claude-opus-5         -> claudeopus5
        "Claude Opus 5 (Amazon Bedrock Edition)"    -> claudeopus5

    Normalizing at BOTH write and lookup time means one row serves a bare model id and
    every cross-region profile of it, so there is no need to duplicate rows per prefix.
    """
    if not name:
        return ""
    s = name.strip()
    s = re.sub(r"\s*\(amazon bedrock edition\)\s*$", "", s, flags=re.IGNORECASE)
    s = s.split("/")[-1]                        # strip gateway target prefix
    s = re.sub(r"^(us|eu|apac|ap|global)\.", "", s, flags=re.IGNORECASE)  # xregion prefix
    s = re.sub(r"^[a-z0-9]+\.", "", s, flags=re.IGNORECASE)               # provider
    s = re.sub(r"-mantle$", "", s, flags=re.IGNORECASE)
    s = re.sub(r":\d+$", "", s)                 # :0 version suffix
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _strip_region_prefix(usagetype: str) -> str:
    m = re.match(r"^[A-Z]{2,4}\d?-(.+)$", usagetype)
    return m.group(1) if m else usagetype


def _legacy_map(records: list) -> dict:
    out = {}
    for rec in records:
        attrs = rec.get("product", {}).get("attributes", {})
        usagetype = attrs.get("usagetype", "")
        low = usagetype.lower()
        # Batch / custom-model / provisioned rates are a different billing model.
        # NOTE: `-mantle-` is deliberately NOT excluded — see the module docstring.
        if "batch" in low or "custom-model" in low or "cross-region-global" in low:
            continue
        component = _LEGACY_COMPONENTS.get(attrs.get("inferenceType", ""))
        if component is None:
            continue
        price, unit = _price_and_unit(rec.get("terms", {}).get("OnDemand", {}))
        if price is None:
            continue
        stripped = _strip_region_prefix(usagetype)
        key = stripped
        for pat in _LEGACY_SUFFIXES:
            new = re.sub(pat, "", stripped, flags=re.IGNORECASE)
            if new != stripped:
                key = new
                break
        out.setdefault(_model_key(key), {})[component] = _per_1k(price, unit)
    return out


def _fm_map(records: list) -> dict:
    """{model_key: {scope: {component: per_1k}}} from both usagetype forms."""
    out = {}
    for rec in records:
        attrs = rec.get("product", {}).get("attributes", {})
        usagetype = attrs.get("usagetype", "")
        servicename = attrs.get("servicename", "")

        # Reserved / provisioned throughput is priced per TPM-hour, not per token.
        if "Reserved" in usagetype or "TPM" in usagetype:
            continue

        component = scope = None
        m = _FM_OLD.search(usagetype)
        if m:
            if m.group("batch"):
                continue
            component = _FM_OLD_COMPONENTS[m.group("component")]
            scope = "global" if m.group("scope") else "regional"
        else:
            m = _FM_NEW.search(usagetype)
            if not m:
                continue
            if m.group("tier") == "batch":
                continue
            # Only standard throughput is metered here; flex/priority carry their own
            # rates and would collide on the same key.
            if m.group("tier") not in (None, "standard"):
                continue
            component = m.group("component")
            if component == "cache_write" and m.group("ttl"):
                component = "cache_write_1h"
            scope = "global" if m.group("scope") else "regional"

        price, unit = _price_and_unit(rec.get("terms", {}).get("OnDemand", {}))
        if price is None:
            continue
        key = _model_key(servicename)
        if not key:
            continue
        out.setdefault(key, {}).setdefault(scope, {})[component] = _per_1k(price, unit)
    return out


def _usable(entry: dict) -> bool:
    """Input must be strictly positive: a $0.00 input rate is a placeholder SKU, and
    accepting it would silently zero out all cost for that model. Output may be $0.00
    (embeddings produce no billable output)."""
    return bool(entry) and entry.get("input", Decimal(0)) > 0 and "output" in entry


def _write(key: str, prices: dict, source: str, scope: str) -> None:
    item = {
        "model_key": {"S": key},
        "input_per_1k": {"N": str(prices["input"])},
        "output_per_1k": {"N": str(prices["output"])},
        "source": {"S": source},
        "rate_scope": {"S": scope or "n/a"},
        "refreshed_at": {"N": str(int(time.time()))},
        "refreshed_iso": {"S": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
    }
    for comp, col in (("cache_read", "cache_read_per_1k"),
                      ("cache_write", "cache_write_per_1k"),
                      ("cache_write_1h", "cache_write_1h_per_1k")):
        if comp in prices:
            item[col] = {"N": str(prices[comp])}
    _ddb.put_item(TableName=_TABLE, Item=item)


def handler(event, context):
    loc = _location()
    fm = _fm_map(_fetch(_FM_CODE, [
        {"Type": "TERM_MATCH", "Field": "location", "Value": loc}]))
    legacy = _legacy_map(_fetch(_LEGACY_CODE, [
        {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Amazon Bedrock"},
        {"Type": "TERM_MATCH", "Field": "location", "Value": loc}]))
    print(f"price maps: fm_keys={len(fm)} legacy_keys={len(legacy)} scope={_RATE_SCOPE}")

    written, by_source, with_cache = 0, {"fm": 0, "legacy": 0}, 0
    for key in sorted(set(fm) | set(legacy)):
        prices, source, scope = None, "", ""
        # Prefer the foundation-models source: current generations + real cache rates.
        for want in (_RATE_SCOPE, "global", "regional"):
            cand = (fm.get(key) or {}).get(want)
            if cand and _usable(cand):
                prices, source, scope = cand, _FM_CODE, want
                break
        if not prices:
            cand = legacy.get(key)
            if cand and _usable(cand):
                prices, source, scope = cand, _LEGACY_CODE, "regional"
        if not prices:
            continue
        _write(key, prices, source, scope)
        written += 1
        by_source["fm" if source == _FM_CODE else "legacy"] += 1
        if any(c in prices for c in ("cache_read", "cache_write", "cache_write_1h")):
            with_cache += 1

    # A heartbeat row so the interceptors (and an alarm) can detect staleness.
    _ddb.put_item(TableName=_TABLE, Item={
        "model_key": {"S": "_META"},
        "refreshed_at": {"N": str(int(time.time()))},
        "refreshed_iso": {"S": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        "models_written": {"N": str(written)},
        "rate_scope": {"S": _RATE_SCOPE},
        "region": {"S": _REGION},
    })

    result = {"written": written, "by_source": by_source,
              "with_cache_rates": with_cache, "rate_scope": _RATE_SCOPE}
    print(f"pricing sync complete: {json.dumps(result)}")
    return result
