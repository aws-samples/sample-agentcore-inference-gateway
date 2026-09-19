"""Cost rollup — an OUT-OF-BAND aggregator, deliberately NOT in the interceptors.

WHY THIS LAMBDA EXISTS
----------------------
The two interceptors are on the request/response hot path and must stay lean and fail
closed — the request interceptor's own timeout was measured to make the GATEWAY fail
*open*, so every millisecond of non-essential work there is a liability. Aggregating
per-user cost history is exactly the kind of non-essential work that must live somewhere
else. So it lives here, on an EventBridge schedule, reading what the interceptors already
wrote and never touching their code path.

WHAT IT PRODUCES
----------------
Two things the fast path cannot answer on its own:

  1. **History beyond 24 hours.** The `DECISION#` records in the ledger carry a 24h TTL
     (they are the console's fast operational copy). This rollup reads them while they
     live and folds their cost into durable per-user daily and monthly aggregates that
     survive long after the source rows expire — so the console can look back weeks.

  2. **A sub -> username map.** The live spend counters are keyed by the Cognito `sub`
     (a UUID), because that is the only identifier the interceptor has cheaply on the
     hot path. `DECISION#` and `PENDING#` rows carry BOTH `sub` and `username`, so this
     job harvests the pairing off-path and writes a small map the console reads to show
     names instead of UUIDs.

TABLE SHAPE (acgw-pilot-cost-rollup)
------------------------------------
  pk = "USER#<username>", sk = "D#YYYYMMDD"   -> {cost_usd, requests, updated_at, ttl}
  pk = "USER#<username>", sk = "M#YYYYMM"      -> {cost_usd, requests, updated_at, ttl}
  pk = "SUBMAP",          sk = "<sub>"         -> {username, updated_at, ttl}

Aggregates are RECOMPUTED (SET), not incremented (ADD): the job re-derives each
day/month total from the decision records it can currently see, so a re-run is
idempotent and a missed run self-heals on the next pass. The only rows it cannot rebuild
are days whose decision records have fully aged out — those keep the last value written
while they were still visible, which is the point of persisting them.

FAIL SOFT, by contrast with the interceptors. This job is not in any request path, so a
failure here degrades reporting, never enforcement. Errors are logged and the next
scheduled run retries.
"""
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import boto3

_REGION = os.environ.get("AWS_REGION", "us-east-1")
_LEDGER_TABLE = os.environ["COST_LEDGER_TABLE"]
_ROLLUP_TABLE = os.environ["COST_ROLLUP_TABLE"]
# How long an aggregate row lives after its last update. Long enough to look back a year
# or more; the daily rows are the bulk, so this bounds table growth without losing the
# monthly history a reviewer actually asks for.
_ROLLUP_TTL_SECONDS = int(os.environ.get("ROLLUP_TTL_SECONDS", str(400 * 86400))
                          or 400 * 86400)

_ddb = boto3.client("dynamodb", region_name=_REGION)


def _day_key(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m%d")


def _month_key(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m")


def _scan_ledger() -> list:
    items, kwargs = [], {"TableName": _LEDGER_TABLE}
    while True:
        page = _ddb.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return items


def handler(event, context):
    """Recompute per-user daily/monthly cost aggregates and the sub->username map."""
    now = int(time.time())
    ttl = now + _ROLLUP_TTL_SECONDS

    try:
        items = _scan_ledger()
    except Exception as exc:  # noqa: BLE001
        print(f"rollup: ledger scan failed ({exc}); nothing written")
        return {"ok": False, "error": str(exc)[:200]}

    # (username, day)  -> {cost, requests}
    daily = defaultdict(lambda: {"cost": 0.0, "requests": 0})
    # (username, month) -> {cost, requests}
    monthly = defaultdict(lambda: {"cost": 0.0, "requests": 0})
    submap = {}   # sub -> username

    decisions = 0
    for it in items:
        pk = it.get("pk", {}).get("S", "")
        if not pk.startswith("DECISION#"):
            continue
        decisions += 1
        username = it.get("username", {}).get("S", "") or "?"
        sub = it.get("sub", {}).get("S", "")
        if sub and username and username != "?":
            submap[sub] = username
        try:
            ts = int(float(it.get("ts", {}).get("N", "0")))
        except (TypeError, ValueError):
            ts = now
        if not ts:
            ts = now
        # Only requests that actually cost something contribute to spend; every decision
        # counts toward the request tally so the aggregate carries volume too.
        try:
            cost = float(it.get("cost_usd", {}).get("N", "0") or 0)
        except (TypeError, ValueError):
            cost = 0.0
        dk, mk = _day_key(ts), _month_key(ts)
        daily[(username, dk)]["cost"] += cost
        daily[(username, dk)]["requests"] += 1
        monthly[(username, mk)]["cost"] += cost
        monthly[(username, mk)]["requests"] += 1

    written = 0

    def _put(pk: str, sk: str, attrs: dict) -> None:
        nonlocal written
        item = {"pk": {"S": pk}, "sk": {"S": sk}, "ttl": {"N": str(ttl)}}
        item.update(attrs)
        try:
            _ddb.put_item(TableName=_ROLLUP_TABLE, Item=item)
            written += 1
        except Exception as exc:  # noqa: BLE001
            print(f"rollup: put {pk}/{sk} failed ({exc})")

    for (username, dk), agg in daily.items():
        _put(f"USER#{username}", f"D#{dk}", {
            "cost_usd": {"N": str(round(agg["cost"], 6))},
            "requests": {"N": str(agg["requests"])},
            "updated_at": {"N": str(now)},
        })
    for (username, mk), agg in monthly.items():
        _put(f"USER#{username}", f"M#{mk}", {
            "cost_usd": {"N": str(round(agg["cost"], 6))},
            "requests": {"N": str(agg["requests"])},
            "updated_at": {"N": str(now)},
        })
    for sub, username in submap.items():
        _put("SUBMAP", sub, {
            "username": {"S": username},
            "updated_at": {"N": str(now)},
        })

    print(f"rollup: {decisions} decision rows -> {len(daily)} daily, "
          f"{len(monthly)} monthly, {len(submap)} sub-map rows; wrote {written}")
    return {"ok": True, "decisions": decisions, "daily": len(daily),
            "monthly": len(monthly), "submap": len(submap), "written": written}
