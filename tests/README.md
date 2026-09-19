# Tests

Four checks, every one of them written because a real bug got past review.

Two run offline in about a second and should be run on every change; two need a deployed
stack and cost a few cents of real inference.

| file | needs AWS | guards |
|---|---|---|
| `test_usage_parsing.py` | no | usage is recovered from every response framing, and priced across all five billable quantities |
| `test_cost_symmetry.py` | no | every deny path refunds its reservation — enforced structurally |
| `verify_operation_coverage.py` | yes | no surface/operation is served without being governed |
| `verify_cost_symmetry_live.py` | yes | a denied request leaves the ledger unchanged, end to end |

## `test_usage_parsing.py` — offline, no AWS, run it every time

Validates that the RESPONSE interceptor recovers token usage from **every** response framing
the gateway can return: buffered Anthropic JSON, buffered Converse JSON, SSE (`data:` frames),
and AWS binary event-stream in both of its flavours — `converse-stream`, which puts event JSON
directly in the frame, and `invoke-with-response-stream`, which wraps each chunk as
`{"bytes":"<base64>"}` so the numbers are not present as text at all.

```powershell
.\.venv\Scripts\python.exe tests\test_usage_parsing.py
```

It loads `pilot/lambda/usage/index.py` directly, so it needs no deployment and costs nothing.

**`fixtures_converse_stream.bin` is a captured live response, and that is the point.** The
first version of this parser passed a purely synthetic test and still failed in production,
because the synthetic fixture omitted `serverToolUsage:{}` — a nested object inside `usage`
that the regex could not match. The test encoded the assumption instead of the payload. Keep
the real fixture, and if you change the parser, re-capture rather than hand-edit it.

The negative cases matter as much as the positive ones: an empty body, binary garbage and JSON
with no usage block must all yield zeros. A parser that invents usage is worse than one that
finds none, because an unmeasurable success is *supposed* to fall back to the worst-case charge.

It also covers the **cost arithmetic**, because prompt caching bills five distinct quantities
and not two: input, output, cache read, and cache write at the *5-minute* and *1-hour* TTL
tiers. The reconciler priced both write tiers at the 5-minute rate while already fetching the
1-hour rate from the pricing table and discarding it, which under-charged 1-hour caching by
about 60% of its cache-write line. The math lives in a pure `_price_usage(usage, rates)`, which
is what makes it testable at all, and the cases pin the tier *ordering*
(`read < input < write5m < write1h`) as well as the totals — including under the multiplier
fallbacks, where an earlier draft let a missing rate mean **free**.

## `test_cost_symmetry.py` — offline, no AWS

Guards the refund. The reservation is taken at CONTROL 3 and several controls can still deny
after it, so every late denial used to bill the caller for output that was never generated —
worst of all `cost_budget_exceeded`, which charged you a second time for being told you were
over budget.

The arithmetic half is ordinary: with a stubbed DynamoDB client, `_refund_reservation` must
write the exact negative of the charge to **both** calendar counters the reservation went to
(daily `<sub>#D#YYYYMMDD` and monthly `<sub>#M#YYYYMM`), using `ADD`, and must write nothing
for a counter whose key the reservation does not carry (guessing a key would credit the wrong
counter). Symmetry is load-bearing: an asymmetric add/subtract drives one counter negative, and
a negative total silently disables its cap.

The **structural** half is the one that matters. It parses the interceptor with `ast` and fails
if any `return` in `_govern` after the reservation does not funnel through `_finish`. A
per-deny-path refund would have worked on the day it was written and been forgotten by the next
control added — which is exactly how the bug arose — so the seam is enforced by the test suite
rather than by reviewer attention. It also asserts `handler` unwinds a stranded reservation,
since the raise paths skip `_finish` entirely and write no `PENDING#` row.

```powershell
.\.venv\Scripts\python.exe tests\test_cost_symmetry.py
```

## `verify_operation_coverage.py` — live, needs a deployed stack

Drives every endpoint surface × API operation and separates two things that are easy to
conflate:

- **governed** — the interceptor evaluated it and wrote a `DECISION#` record
- **served** — the target actually dispatched it to a model

Governed-but-not-served is fine (the provider target declares only the Messages operation).
**Served-but-not-governed is a bypass**, and this is the only check that would catch a newly
added operation slipping through. It also asserts that an unentitled caller is refused on every
surface, and reports which operations produced output-token accounting — which is how the
streaming accounting bug was found.

```powershell
.\.venv\Scripts\python.exe tests\verify_operation_coverage.py
```

Costs a few cents of real inference and writes real audit records.

## `verify_cost_symmetry_live.py` — live, needs a deployed stack

The end-to-end half of `test_cost_symmetry.py`: it drives each denial path against the deployed
gateway and asserts the caller's **daily and monthly** spend counters are both unchanged,
reading the ledger rows `<sub>#D#YYYYMMDD` and `<sub>#M#YYYYMM` directly. Those rows are what
enforcement reads, so they are the thing that has to be right; a `refunded: true` log line would
only prove we logged it.

Five scenarios. A baseline allowed request first, which must move the day and month counters by
the **same** amount (the direct test of the symmetry hazard above), then the denials ordered by
how late they land — model entitlement (before the reservation), guardrail (after it), cost
budget (the worst case), and Cedar (after the request interceptor has already returned ALLOW, so
only the RESPONSE interceptor can reverse it). Then it scans for unsettled `PENDING#` rows: such
a row means "in flight", so one that outlives its request is a reservation nobody settled.

The entitlement and budget scenarios each install a temporary `USER#bob` config row to force
the denial and restore whatever was there afterwards. They do not assume the deployed rows will
deny: resolution is first match per kind with no merge, so a permissive `GROUP#` row saved from
the console out-ranks a `DEFAULT` deny for its members — documented behaviour that once made
this scenario report a `200` and look like a bypass.

```powershell
$env:ACGW_DEMO_PASSWORD = "<the DemoUserPassword stack output>"
.\.venv\Scripts\python.exe tests\verify_cost_symmetry_live.py
```

⚠️ **Read `SKIPPED` as "not proven", not as "fine".** A scenario is only measurable if its
before and after reads land in the same UTC day; each one refuses to start in the last minute
of the day and reports `SKIPPED (UTC day rolled)` rather than silently comparing two different
counters — which would read as a clean PASS.

Takes a couple of minutes, mostly the interceptor's config-cache TTL and settle waits.
