# AgentCore Gateway Inference — Findings

Hard-won, empirically-verified intelligence. Each item = what we tried, what
actually happens, and the mechanism. This is the pilot's most valuable output.
Status legend: ✅ works / ⚠️ works with caveat / ❌ blocked (with reason).

## 🔥 A REQUEST-INTERCEPTOR TIMEOUT FAILS **OPEN** — measured, and undocumented

**This is the single most important thing in this document.** If you are building governance on
an AgentCore Gateway request interceptor, read this before you trust it.

The AWS devguide does not state what the gateway does when the interceptor fails to return a
verdict. It says only that the gateway *"may retry requests to interceptor Lambda functions in
case of failures or timeouts"*. So we measured all three failure modes directly.

| Interceptor state | How it was induced | Gateway result | Model reached? |
|---|---|---|---|
| **Throttled** (cannot be invoked) | `put_function_concurrency(ReservedConcurrentExecutions=0)` | `400` — **fail closed**, both surfaces | no |
| **Errors** (unhandled exception) | `update_function_configuration(Handler="index.nope")` | `400` — **fail closed** | no |
| **Times out** | `update_function_configuration(Timeout=1)` | **`200` — FAIL OPEN** | **yes, ungoverned** |

The third row returned a real completion from Bedrock in 3.2s. No entitlement check, no guardrail,
no metering, no audit record. (Amusing tell: the response contained an emoji, which blew up the
test script's cp1252 stdout encoding — that is how we knew a model had genuinely answered rather
than the gateway synthesising something.)

**Why this is the failure mode that matters.** Throttling and unhandled exceptions are pathological
— you would notice them in minutes. A *timeout* is the one that happens on an ordinary Tuesday: a
slow `ApplyGuardrail`, a DynamoDB latency spike, a cold start under load. The failure mode most
likely to occur in production is the one the gateway resolves by letting traffic through unchecked.

**There is no gateway setting to change this.** `GatewayInterceptorConfigurationProperty` exposes
`interceptionPoints`, `interceptor` and `inputConfiguration` (`passRequestHeaders`, `payloadFilter`)
— and nothing about failure behaviour. Verified by introspecting the installed construct.

### The corollary that inverted our error handling

The interceptor used to wrap the config read, the rate counter, the ledger write and the guardrail
call in `try/except` blocks that logged and then **allowed**. Given the table above, every one of
those handlers was **worse than having no handler at all**: an unhandled exception already fails
closed at the gateway, so catching it and passing through *converted a safe gateway default into
an unsafe one*. They are all deleted. Removing error handling made the system safer, which is not a
sentence one writes often.

### What we do instead: never let the runtime kill us

The invariant the interceptor now holds:

> **The interceptor must never be killed by the Lambda runtime. It must always return a verdict itself,
> and that verdict defaults to deny.**

Three mechanisms, all in `pilot/lambda/guardrail/index.py`:

1. **A self-imposed deadline.** `_Deadline` wraps `context.get_remaining_time_in_millis()` — the
   only honest source, because it accounts for cold-start time already spent, which a `time.time()`
   baseline taken inside the handler does not. `deadline.ensure(control)` is called before each
   control and raises `_OutOfTime` if `remaining < estimated_cost + safety_margin`.
2. **Per-dependency timeouts.** Explicit `connect_timeout` / `read_timeout` / `max_attempts` on the
   boto3 clients, so one hung service cannot consume the whole budget. `ApplyGuardrail` gets
   **one attempt only** — a retry would double the worst case, and the deadline is a better backstop
   than a second try.
3. **A thin fail-closed wrapper.** `handler` does nothing but call `_govern` and convert anything it
   raises into a typed denial. New controls added inside `_govern` therefore cannot introduce a
   fail-open path by forgetting to handle something.

The Lambda `timeout` is now **headroom, not a deadline** (20s, `config.INTERCEPTOR_TIMEOUT_SECONDS`).
It exists only so the internal deadline is always what fires first.

**Verified after the change:** with the Lambda timeout cut to 3s, 4/4 requests returned
`403 governance_timeout` — where previously they returned `200` with the model invoked. The audit
record carries `control=deadline`, `fail_closed=true`, `remaining_ms=2999`, and the arithmetic:
`"2999ms left, config needs ~4500ms including a 2000ms margin"`.

### Denials now distinguish "not allowed" from "could not tell"

`_closed_response` is deliberately separate from the guardrail and entitlement blocks, because the
two mean different things operationally. A spike of `model_access_denied` is users hitting policy;
a spike of `governance_unavailable` is an **incident**. New decisions to alarm on:

| Decision | Meaning |
|---|---|
| `governance_timeout` | ran out of budget before a control could be evaluated |
| `governance_unavailable` | a dependency failed; policy could not be established |
| `governance_retry_indeterminate` | a retry arrived whose first attempt recorded no outcome |
| `unrecognised_shape` | no prompt text AND the request shape was not recognised |
| `no_body` / `unparseable_body` | nothing to govern; refused rather than forwarded |
| `breakglass_bypass` | an administrator has deliberately disabled enforcement |

### ⚠️ Gateway retries make non-idempotent controls unsafe

Taking the devguide's retry warning seriously: both mutating controls were `ADD` operations
(`ADD tokens, requests` on the rate counter; `ADD spend` on the ledger). Neither is idempotent, so
a single retry double-charges a user and double-consumes their rate allowance.

Now guarded by `_claim_request()`: a conditional `PutItem` on `SEEN#<request_id>`. Winning the
condition means first attempt; losing it means replay the stored verdict instead of re-charging. A
retry whose first attempt stored *no* verdict — i.e. the one that timed out — fails closed, because
we cannot know whether it already charged.

**Unverified assumption, stated plainly:** this depends on the gateway reusing `REQUEST_ID` across
retries of the same caller request. The API offers no way to induce a retry on demand, so this is
defence rather than a guarantee. If the gateway mints a fresh id per attempt, the guard silently
does nothing — it never makes things worse, but it would not help either.

### The availability trade, and the break-glass switch

A fail-closed governance plane is one interceptor bug away from a total inference outage. That is
only an acceptable trade if recovery is faster than shipping code, so there is a
`(DEFAULT, BREAKGLASS)` config row with `enabled` / `reason` / `set_by`. Flipping it bypasses
enforcement within the config cache TTL (~10s), no deployment.

It is checked **first**, before the body is even parsed — that is deliberate, because "the
interceptor is rejecting everything including malformed bodies" is exactly the situation someone
breaks glass for. Every bypassed request writes `decision=breakglass_bypass` carrying `set_by` and
`reason`, so turning it on is loud and attributable, and leaving it on is one query away from
being noticed.

**Verified live:** `bob` → premium `403` → flip → `200` → unflip → `403`, with the audit record
present each time.

## ⚠️ GOVERNANCE BYPASS BY REQUEST SHAPE (found and fixed) — the most useful bug so far

**Symptom.** A call to `/inference/v1/responses` produced **no decision record at all**, while the
same user's `/inference/v1/messages` call produced one. Nothing errored; the request simply was
not governed.

**Cause.** The REQUEST interceptor extracted prompt text and then did:

```python
text_units = _extract_text_units(body)
if not text_units:
    return _passthrough()          # <-- sat BEFORE cost check and guardrail
```

`_extract_text_units` understood `messages[]` and `system` only. The OpenAI **Responses API**
carries its prompt in `input` / `instructions`, so nothing was extracted and the request skipped
**cost accounting, guardrail evaluation and decision recording** in one step.

**Why it was easy to miss.** Model entitlement runs *before* extraction, so denials still worked
perfectly — `bob` got a correct `403` through the Responses shape. Only *allowed* requests were
unguarded. Testing the deny path proved nothing about the bypass.

**Fix.**
- A single `_normalize()` reduces any accepted shape to
  `{model, text_units, tool_specs, max_output_tokens}`, harvesting text by **structure** rather
  than by known field names, and skipping opaque keys (`bytes`, `source`, `s3Location`) so image
  base64 is never scanned.
- Path matching is generic in the **verb**, so a new runtime operation still resolves its model.
- The early return is **gone**. An unrecognised shape no longer skips cost, recording or audit.
- An unresolvable model is now `403 model_unresolved` (CONTROL 0) rather than an allow.

**"No text extracted" is now split into two cases**, which the first fix conflated:

| Cause | Verdict |
|---|---|
| Shape **recognised**, genuinely no caller text (image-only turn) | allow + record `allowed_no_prompt_text` — denying would break legitimate traffic |
| Shape **not recognised** (`api_shape` ends `?`, or `unknown`) | `403 unrecognised_shape` — the absence of text cannot be trusted |

**Verified after the fix** (8 requests, 16 audit records): `anthropic.messages`,
`openai.chat.completions`, `openai.responses` and `bedrock.invokemodel` all show
`guardrail_evaluated: true`, and guardrail denials fire on **both** surfaces.

**The general lesson.** A control that reads the request body inherits every body format the front
door accepts. The gateway routes three inference contracts plus passthrough; enumerate them,
harvest structurally, and make the unparsed case **fail closed**.

## Interceptor buffering is NOT tunable — ❌ no knob exists

The response interceptor buffers the entire response on inference targets, and there is **no
chunk size or threshold to lower**. `InterceptorInputConfiguration` exposes exactly two
properties, `passRequestHeaders` and `payloadFilter` — neither affects buffering.

AWS documents the constraint plainly. Inference targets fall under the HTTP-target contract
("Inference is a separate target type that happens to share the HTTP interceptor payload shape"),
and for those, response interceptors are *"Supported in buffered mode (not yet supported in
streaming mode)"*.

**Per-event interception does exist — but only for MCP.**
`protocolConfiguration.mcp.streamingConfiguration.enableResponseStreaming` makes the response
interceptor fire once per stream event rather than once with the complete response. In CDK the
shape confirms the scoping: `StreamingConfigurationProperty` is reachable only through
`GatewayProtocolConfigurationProperty(mcp=MCPGatewayConfigurationProperty(streaming_configuration=...))`.
Its semantics are JSON-RPC specific too — invoked only for events carrying an `id`, skipped for
`notifications/progress`, `notifications/message` and pings, and only the first event may override
headers or status code. None of that reaches an inference gateway.

So the streaming trade-off is **binary today**: attach the response interceptor and get true
output-token cost, or omit it and get progressive streaming. If per-event interception arrives for
inference targets, that is the mechanism to revisit — not a buffer size.

**Related hard limit worth designing around:** Lambda synchronous invocation caps request plus
response at **6 MB**, and a large base64-encoded inference body can exceed it. The documented
escape is a payload filter excluding `RESPONSE_BODY` — which keeps the interceptor alive but
removes the exact field output-token accounting reads. Long generations need either a body-size
ceiling or a different accounting source.

## Central audit log — DELIVERED ✅

One CloudWatch group, `/acgw-pilot/governance-audit`, carries every governance decision and
guardrail intervention, independent of account-level Bedrock logging.

**The wiring trick that made this simple.** Rather than have each Lambda call `PutLogEvents` into
a separate group — extra IAM, a log-stream lifecycle to manage, and a 5 TPS-per-stream throttling
ceiling — both interceptors set the Lambda `logGroup` property to the **same** group. A plain
structured `print` then lands in the single destination. Request and response records for one call
join on `request_id`.

Why the alternatives do not work:

| Candidate | Why it fails as the audit record |
|---|---|
| Bedrock invocation logging | Account-level setting this stack does not own; mantle does not offer it; records the Bedrock *call*, so a guardrail denial — which never reaches Bedrock — is absent entirely. |
| Gateway OTEL spans | No identity, no token counts, and interceptor short-circuits are not spanned. |
| DynamoDB decision records | 24-hour TTL by design — operational state for the console, not an archive. |

Design choices worth keeping:

- **Prompt text off by default.** Records always carry `prompt_sha256` + `prompt_chars`, which is
  enough to correlate requests and detect tampering without concentrating the most sensitive data
  in the system into a log group. `AUDIT_LOG_PROMPT_TEXT` opts in deliberately.
- **90-day retention** with field indexes on `request_id`, `username`, `decision`, `model`.
- **Every verdict says which way it failed.** `fail_closed: true` on a denial we made because we
  could not evaluate policy; `fail_open: true` on the *only* remaining bypass, the break-glass
  row. Since the interceptor became fail closed there is almost nothing in the second category —
  which is the point. "What did we allow without a verdict" is one query, and the expected answer
  is now zero unless an operator has deliberately broken glass.

**Two limits, measured:**

1. ~~**Cedar denials are not attributable.**~~ **Fixed — see "Resolving the true final outcome"
   below.** The interceptor still runs *before* Cedar, so its own record still says
   `allowed / 200`, but the RESPONSE interceptor now stamps the true outcome and the deciding
   layer onto both the decision record and the audit record. What remains is narrower: a denial's
   RESPONSE record carries no `username`, because the response event has none and the reconcile
   path that would supply it does not run on a denial. Join on `request_id` for the user.
   The ordering consequence is unchanged: the interceptor charges cost for requests Cedar
   then denies.
2. **Logs Insights lags ingestion.** Immediately after driving 8 requests, Insights returned 10 of
   16 records while `get_log_events` returned all 16. Wait 1–2 minutes before trusting a query.

## ⚠️ Docs contradiction: RESPONSE interceptor DOES run after a short-circuit

AWS documentation states, for HTTP targets: *"If `transformedGatewayResponse` is present in a
REQUEST interceptor's output, the gateway returns that response immediately without calling the
target (a short-circuit). The RESPONSE interceptor does not run after a short-circuit."*

**Measured behaviour is the opposite.** Four denials — two guardrail blocks, one entitlement
denial, one Cedar denial — each produced a RESPONSE-stage audit record alongside the REQUEST-stage
one. This matches the *MCP* section of the same page, which says the response interceptor "will
still be invoked".

Practical consequence, and it turned out to be load-bearing: the response side sees denials, so
it is able to reverse a reservation for a denial the request side never saw — a **Cedar** refusal
or an upstream `4xx`, both of which happen after the REQUEST interceptor has already returned
ALLOW. Without that, those two paths would have no refund path at all.

But the two statements in the docs disagree, so do not depend on either without testing. Note
what the dependency actually is: if the documented behaviour were the real one, denials would be
over-charged rather than *allowed*, so relying on this is a correctness risk for the ledger and
never a bypass risk for enforcement.

## TRUE-COST ACCOUNTING (output tokens) — DELIVERED

Cost governance originally charged the **prompt only**, because output tokens do not exist
when the request interceptor runs. That understates real spend badly: measured on one
request, **prompt-only was 105x too low** (input 24 tokens vs output 500), and across the
verification runs **95% of all tokens were output**.

### Architecture: a second, separate RESPONSE interceptor
`pilot/lambda/usage/index.py`, wired as a **second interceptor configuration** on the same
gateway (`interception_points=["RESPONSE"]`). Two configs on one gateway are accepted. Kept
separate from the enforcement interceptor deliberately — different job, different
interception point, and the enforcement path stays unaffected.

### ❌ The response interceptor has NO identity — attribution had to be solved
Probed the real payload: `http.gatewayRequest` is **`None`**, even with
`pass_request_headers=True`. So there is no JWT, no path, no user. `gatewayResponse` carries
only `body`, `contentType`, `headers` (empty), `statusCode`. Response headers were empty, so
nothing there to join on either.
- ✅ **Solved via `REQUEST_ID` in Lambda client context.** Both interceptors receive
  `{GATEWAY_ARN, GATEWAY_ACCOUNT_ID, REQUEST_ID, SOURCE_IP}`, and the REQUEST_ID is
  **identical on both sides** (verified: `ffcaeff0-...` in both logs). The request side parks
  identity under `PENDING#<REQUEST_ID>` (15 min TTL); the response side joins on it.

### Reserve-then-reconcile (not charge-then-hope)
First implementation charged prompt-only at request time and added output cost afterwards.
That let enforcement **lag by a request** — observed: mantle allowed 2 large calls before
blocking, because the budget check can only see spend already reconciled.
- Fixed by **reserving** worst-case output cost from the caller's declared `max_tokens` at
  request time, then reconciling to actuals (applying the *difference*, so nothing is
  double-counted). Mirrors how the gateway's own token limits behave.
- ✅ VERIFIED identically on both surfaces: 3 calls allowed, 4th blocked at
  `$0.0242 of $0.0200`. Reservation tracks actuals closely (est 0.00603 vs true 0.00606).

### ❌→✅ Streaming responses were escaping accounting entirely
Caught by a stray `leftover pending: 6` in the notebook output. Cause: a streaming response
body is an **SSE event stream, not JSON**, so there is no top-level `usage` to read — the
interceptor logged "no usage block" and neither charged nor cleaned up. Every streaming
request was therefore uncounted.
- ✅ Fixed with an SSE parser: `message_start` carries `input_tokens`, `message_delta`
  carries the running `output_tokens`; take the input from the first and the **last** output
  value (the final total). Verified: a streaming request now records in=27 out=300
  true=$0.004581.
- Also added `_release_reservation()`: if usage genuinely cannot be parsed, **refund** the
  reservation rather than leave the user charged for output they may never have received.
  ⚠️ **That last decision was wrong and has since been reversed** — refunding an unparseable
  *success* is what later became a free-inference bypass, because a body the parser could not
  read still had a model generate it. See "the refund was on the wrong branch" below;
  `_release_reservation` is now `_settle_reservation(request_id, refund: bool)`.

### ⚠️ The trade-off, measured
Response interception on HTTP/inference targets is **buffered**, so enabling this costs
progressive streaming:

| | request-only | + response interceptor |
|---|---|---|
| SSE events / chunks | 248 / 119 | 248 / 119 |
| First token | 2.7s | **7.4s** |
| Spread | **5.4s** (progressive) | **0.0s** (all at once) |

Nothing breaks — same SSE format, complete content — but time-to-first-token roughly
triples and every chunk lands together. `config.ENABLE_OUTPUT_TOKEN_ACCOUNTING = False`
reverses the choice. **Accurate spend control costs streaming; that is the decision.**

### Also worth knowing
- The native tier/model `rate:0` limit was **removed** (it contradicted the config table).
  Section 4 of the notebook is annotated accordingly.
- Config seeding is create-only, so raising the demo budget in code required an **admin API
  edit** to take effect on an existing table — the intended path, and a good demonstration
  of the trade-off.

---

## MODEL PRICING IS RUNTIME STATE TOO — and the constants were 3x wrong

Costing a request needs a price per token. The first version hardcoded those as Python
constants, which was wrong in the most boring and most expensive way:

| Model | Hardcoded (in / out per 1K) | Actual | Error |
|---|---|---|---|
| `claude-sonnet-5` | `0.003` / `0.015` | `0.002` / `0.010` | 1.5x over |
| `claude-opus-5` | `0.015` / `0.075` | `0.005` / `0.025` | **3x over** |

A budget built on a 3x-wrong rate is not a budget. So prices became runtime state: a
DynamoDB table (`acgw-pilot-model-pricing`, pk = normalized `model_key`) refreshed daily
from the **AWS Price List API** by `acgw-pilot-pricing-sync` on an EventBridge schedule,
and primed once on create so a fresh deploy never runs on fallbacks. 110 rows (109 models
plus a `_META` heartbeat).

### ⚠️ Bedrock pricing is split across TWO service codes with different schemas

This is the finding. Query only the obvious one and every current-generation Anthropic
model silently returns nothing:

| Service code | Covers | Unit | Model identified by |
|---|---|---|---|
| `AmazonBedrock` | Nova, Titan, Llama, Mistral, DeepSeek, **legacy** Claude | per **1K** tokens | has `inferenceType` |
| `AmazonBedrockFoundationModels` | **current** Claude (4.x/5.x), Cohere, Jamba, Palmyra | per **1M** tokens | `servicename`, e.g. `"Claude Opus 5 (Amazon Bedrock Edition)"` |

Two traps in that table:
- **Mixing the units misprices by 1000x.** The second source must be divided by 1000.
- The second source has **no `inferenceType`**, so the model has to be recovered from a
  human-readable `servicename` string rather than a model id.

### ⚠️ The second source is mid-migration between two `usagetype` conventions

Both are live simultaneously:

```
old CamelCase:      USE1-MP:USE1_OutputTokenCount_Global-Units
new snake_case:     USE1-MP:USE1_cache_read_tokens_global_standard-Units
```

`claude-sonnet-5` and `claude-opus-5` use the **newer** form. A parser that handles only the
older CamelCase convention yields no price for exactly the models you are most likely to be
running. `pilot/lambda/pricing/index.py` matches both (`_FM_OLD` and `_FM_NEW`).

### Implementation choices worth knowing

- **One row per normalized `model_key`.** `anthropic.claude-opus-5`,
  `us.anthropic.claude-opus-5`, `bedrockprov/anthropic.claude-opus-5` and the `servicename`
  string all normalize to the same key, so one row serves every cross-region variant.
  Normalization happens at both write and lookup.
- **`-mantle-` usagetypes are ingested.** A meter driven by Bedrock *invocation logging*
  would have to skip them, because that logging does not capture mantle. This meters at the
  interceptor, so they are usable.
- **Excluded deliberately:** Reserved/TPM SKUs (unit `1M TPM Hour`), batch, custom-model,
  cross-region-global, and the flex/priority throughput tiers (they collide on the same key —
  see *Remaining work* in the README).
- **A `$0` input rate means a placeholder SKU**, so a row is only usable when input > 0.
  Output and cache rates may legitimately be `$0`.
- **Real cache rates are published**, including the 1-hour-TTL tier: sonnet-5 cache read
  `0.0002` / write `0.0025` / write-1h `0.004`. The multiplier placeholders this replaced
  (`0.1` read, `1.25` write on the input rate) turned out to be exactly right for Anthropic
  but could not express the 1h tier at all.
- **Enforcement continues on the last known rates** if a refresh fails. Falling back to the
  constants would be the worse error; falling back to zero would mean unlimited spend. Rows
  older than `PRICING_STALE_AFTER_SECONDS` (36h) are flagged `price_stale` on the audit
  record rather than being discarded.
- The interceptor falls back to the constants **only** when no row exists, and prints when
  it does, so a silent regression to wrong prices is not possible.

---

## 🔒 SECURITY INCIDENT: a world-accessible Lambda (resolved)

**What happened.** The admin console was first built on a Lambda **Function URL** with
`authType=NONE`. That configuration *requires* a resource policy with `Principal: "*"`,
which made `acgw-pilot-admin-console` world-accessible. Account security tooling (Palisade)
detected it and an automated mitigation (Epoxy) scoped the wildcard principal down to the
owning account. An FYI ticket was raised to the account owners.

**Root cause, stated honestly.** Choosing a Function URL with `authType=NONE` and then
relying on in-code token validation. The reasoning ("the UI shell is public, the data is
not") was not wrong about the data path, but it produced a genuinely public Lambda
**invoke** surface, which is what the detector cares about — and correctly so, since
anything reachable can be probed, fuzzed and billed.

**Why it was already gone before the ticket.** The Function URL never worked in this
account (an org guardrail returns 403 on unauthenticated Function URLs), so the console had
already been migrated to an **API Gateway HTTP API** and the wildcard permission removed.
The exposure was real but transient.

**Remediation applied (not relying on the auto-mitigation).**
1. Verified live state: no `Principal: "*"` on any function, and **no Function URLs** at all.
2. Found and fixed a second, subtler issue of my own making: the usage interceptor's
   permission granted `bedrock-agentcore.amazonaws.com` with **no `SourceArn` condition**,
   so any AgentCore gateway in any account could invoke it. Now scoped to this gateway's ARN.
   (It had been unscoped only because the gateway did not exist yet at that point in the
   constructor — the fix is to grant the permission after the gateway is created.)
3. Added a **synth-time CDK Aspect** (`pilot/guards.py`, `NoPublicLambdaAspect`) so the
   class of regression cannot ship:
   - `add_error` on any Lambda permission with a wildcard principal,
   - `add_error` on any Function URL with `AuthType: NONE`,
   - `add_warning` on a service-principal grant lacking `SourceArn`/`SourceAccount`.

**Verified the guard actually blocks** (a guard that does not fire is worse than none): a
deliberately-bad stack fails with `Synthesis finished with errors`, exit 1, catching all
four violations. Note that **error annotations are enforced by the CDK CLI, not by a bare
`python app.py`** — `app.synth()` in-process collects them without raising, so validate
guards through `cdk synth`/`deploy`.

**Final state:** all three Lambdas COMPLIANT — no wildcard principals, every service
principal constrained by `SourceArn`, zero Function URLs. Inference (both surfaces),
guardrail blocking, and console authorization all re-verified after the change.

**Lesson for the design:** the public surface should be API Gateway (or CloudFront), never
the Lambda itself. "Authorize in code behind a public invoke endpoint" is not equivalent to
"not publicly invokable".

---

## GOVERNANCE CONFIG LAYER + ADMIN CONSOLE (latest)

### Policy data as runtime state ✅
`acgw-pilot-governance-config` (pk=scope, sk=kind) holds MODELS / RATELIMIT / BUDGET /
GUARDRAIL per `DEFAULT | GROUP#<g> | USER#<u>`, resolved **USER > GROUP > DEFAULT** per kind.
The interceptor scans it once per `CONFIG_CACHE_TTL_SECONDS` (10s) per warm container — so the
TTL is the worst-case admin-change-to-enforcement delay, and the steady-state read cost is
~1/TTL rather than 1/request. Fails **closed** on load error: it serves a stale cache if it has
one (ten-second-old policy beats no policy) and raises otherwise, which the handler turns into a
`403`. It must never return an empty config, because the config table is where the *deny* rules
live — "empty config on error" does not mean "no policy", it means **no denials**.
- ✅ VERIFIED with no redeploy, on BOTH surfaces: clearing the premium deny made bob's opus
  calls 200/200 within the TTL; restoring it returned 403/403.
- ✅ Precedence verified: a `USER#bob` allow-all row beat the more general deny.
- ⚠️ `TIER#` scopes existed originally and were REMOVED with the tier axis. Entitlement is now
  expressed as **deny at `DEFAULT`, permit at `GROUP#`**, so access changes with group
  membership rather than with a claim baked into a token.
- ✅ Per-scope guardrails verified (the previously-unimplemented capability): setting
  `USER#alice GUARDRAIL enabled=false` let alice's injection through (200) while bob's
  identical prompt was still blocked (403).
- **One glob spans both surfaces**: `*claude-opus*` matches mantle's
  `anthropic.claude-opus-5` and runtime's `us.anthropic.claude-opus-5`.
- Seeding is **onCreate only** on purpose so redeploys never clobber admin edits. Cost:
  changing a seed value in code has no effect on an existing table.

### ⚠️ A guardrail id is not a guardrail — the version has to travel with it

The `GUARDRAIL` row stored `guardrail_id` and `enabled`, and the interceptor called
`ApplyGuardrail` with `guardrailVersion` taken from its own **environment variable**, baked by
CDK from the guardrail *this stack creates*.

That was coherent while the only bindable guardrail was ours. It stopped being coherent the
moment the admin console could list and bind **any guardrail in the account**: the id then came
from policy while the version came from an unrelated resource's deploy-time state.

**Why it stayed invisible.** Every guardrail in the development account happened to sit at
version `DRAFT`, so the mismatched pair always agreed by accident:

```
acgw-pilot-guardrail      <id>   DRAFT
<other account guardrail>  <id>   DRAFT
<other account guardrail>  <id>   DRAFT
...                        <id>   DRAFT
```

Bind a **published** guardrail and it breaks two ways, the second worse than the first:

| Failure | Effect |
|---|---|
| the version does not exist on that guardrail | `ApplyGuardrail` raises → interceptor **fails closed** → every request in that scope gets `403` |
| the version exists but is not the one previewed | we silently enforce a **different content policy** than the console displayed |

**Fix.** `guardrail_version` is now part of the row, `_guardrail_for` returns the id and version
as a pair, and `_apply_guardrail` takes the version as a **parameter** rather than reading a
module global. The env var remains a fallback, and the fallback is scoped: it applies only when
the resolved id *is* the env default id, because for any other guardrail the env version
describes a different resource. Otherwise the default is `DRAFT` — the one version every
guardrail is guaranteed to have.

Two supporting changes, both about not lying to the operator:

- `_guardrails()` used to de-duplicate `ListGuardrails` by id, discarding every version but the
  first. That is precisely why the picker could not express "bind version 2". It now returns the
  full `versions` list per guardrail.
- `_guardrail_detail` falls back to an unversioned read if the requested version cannot be
  fetched, and now **reports** that (`version_fallback`) so the UI can warn instead of
  presenting the wrong policy as if it were the right one.

**The general shape of this bug:** a compound key where one half is runtime state and the other
is deploy-time state. They drift the moment the runtime half can name something the deploy-time
half never knew about.

### ⚠️ FUTURE ENHANCEMENT: multi-group scope resolution is claim-order dependent

**This is the main thing to fix before putting this in front of a real directory.** It is not a
bug today; it is a design gap that stays invisible at demo scale and becomes silent
misgovernance as groups multiply.

`_scope_chain` builds `USER#<u>` → `GROUP#<g>` *for each group in claim order* → `DEFAULT`, and
`_resolve` returns the **first row it finds** for that kind. There is no `sorted()`, no priority
field, and no reconciliation between groups.

So for a user in several groups that each have a row of the same kind, **the winner is whichever
group the token happens to list first**. Measured on the live pool — `alice` is declared
`[ai-platform, ml-research]` in `config.py`, with `precedence=1` and `2` respectively:

```
cognito:groups as the ACCESS TOKEN presents them:
  ['ml-research', 'ai-platform']

scope chain the interceptor builds:
  0. USER#alice
  1. GROUP#ml-research
  2. GROUP#ai-platform
  3. DEFAULT
```

The order is **reversed from the declaration, and it is not ascending by `precedence` either**.
So the input that decides which policy applies is one nothing in this repo sets, sorts or
validates.

**Why it is latent right now.** Only `GROUP#ml-research` has a `MODELS` row, and `_resolve`
*skips* scopes with no row for the kind it is resolving — it stops at the first scope that has
one. With one row per kind across all groups, order cannot change the outcome. The ambiguity
activates the first time two groups a user belongs to both carry a row of the same kind.

**Why it matters more than it looks.** The intuitive mental model for layered group policy is
"most restrictive wins". This resolves to "first listed wins", which means **adding someone to a
more restrictive group may not restrict them**. That is the kind of defect that passes review
because every individual rule reads correctly.

Two candidate fixes, neither yet implemented:

1. **Explicit priority on the row.** Add a numeric `priority` to each `GROUP#` row and sort the
   chain by it, ties broken deterministically by group name. Most flexible, and it makes the
   precedence visible in the console instead of implied by an invisible claim ordering. Cost: a
   new attribute to seed, migrate and explain.
2. **Deny-wins across all matching scopes.** Stop at no single row; evaluate every matching
   `GROUP#` row and take the most restrictive outcome per kind (union the deny lists, intersect
   the allow lists, take the min budget and the min rate). Matches the intuition and needs no new
   attribute, but it changes `_resolve` from "find one row" to "merge N rows" for every kind, and
   "most restrictive" needs defining per kind — the min of two budgets is obvious, the merge of
   two guardrail bindings is not.

A third option is to sort the chain by Cognito group `precedence` deliberately rather than relying
on claim order. That is the smallest change, but it swaps an undocumented ordering for a
documented one **that this stack derives from dict insertion order** (`precedence=idx + 1` in
`pilot/cognito.py`), so inserting a group in the middle of `COGNITO_GROUPS` renumbers everything
after it. It would need that coupling removed first.

Until one of these lands, the safe operating rule is: **give a user at most one group carrying a
row of any given kind**, and use a `USER#` override for exceptions.
Once model access moved into the config table, the surviving native rate-limit entry meant
an admin could allow a model in the console and it would still be blocked on the mantle
path. Two mechanisms disagreeing about the same question is worse than one imperfect one.
**Update: the per-user TPM limit has since been deleted too** — see the *Rate limits*
section. It answered a different question (prompt volume, not entitlement), but it answered
it on only one of the two surfaces, and that made it a misleading kind of safety net.

### ❌ Lambda Function URLs are blocked in this account (infrastructure finding)
First build used a Function URL with `authType=NONE`. The resource policy was verified
textbook-correct (`Principal "*"`, `lambda:InvokeFunctionUrl`, condition
`lambda:FunctionUrlAuthType = NONE`, and `AuthType: NONE` on the URL) yet **every**
request — including the plain HTML shell — returned:
```
403 {"Message":"Forbidden. For troubleshooting Function URL authorization issues, ..."}
```
That is the Function URL auth layer rejecting the call *before* our code runs. With the
policy provably correct, the cause is almost certainly an **org-level SCP/RCP forbidding
unauthenticated Lambda Function URLs**. Also observed: the function ended up with **no
resource policy at all** after one redeploy (`GetPolicy` → `ResourceNotFoundException`)
even though CDK had created the permission — declaring it explicitly via `add_permission`
made it a tracked resource, but did not fix the 403.
→ **Switched to an API Gateway HTTP API.** Payload format 2.0 has the same
`requestContext.http.method` / `.path` shape as Function URLs, so the handler needed **zero
changes**. `aws_apigatewayv2` and `aws_apigatewayv2_integrations` are stable in
`aws-cdk-lib` (no alpha module needed).

### ❌ INTERCEPTOR DECISIONS ARE NOT EMITTED AS GATEWAY SPANS (important)
Proven directly: issued a Cedar denial (carol) and an interceptor denial (bob → opus) back
to back, waited for span delivery, and got **exactly one 403 span** — the Cedar one
(`errorType=user`). The interceptor's 403 produced **no span at all**.
- Consequence: because model access, guardrails and cost all moved into the interceptor,
  **span-derived "blocked" counts undercount badly.** Measured live: **10 interceptor
  decisions including 6 denials vs. spans showing a single 403.**
- Combined with the earlier finding that spans carry **no identity and no token counts**,
  gateway spans cannot answer "who did what" at all.
- → **Fix implemented:** the interceptor writes a decision record per request
  (`DECISION#<ts>#<uuid>` in the ledger table, 24h TTL) with username, groups, model, path,
  decision, status and the deciding policy scope.
- → **Spans were later dropped from the statistics entirely.** Labelling them *partial*
  alongside a *complete* source still invited the reader to reconcile two tables that cannot be
  reconciled, and once the native rate limits were deleted the only thing spans still
  distinguished (`errorType=throttle`) became impossible. The remaining signal
  (`errorType=user`, i.e. Cedar) is now resolved from the decision records instead. Spans moved
  to an opt-in `/api/diagnostics/spans`, which also removed a ~25s Logs Insights poll from every
  page load.

### Resolving the true final outcome — the console counted Cedar denials as allowed

**A decision record written by the REQUEST interceptor cannot state the request's outcome**,
because two enforcement layers run after it. The record said `allowed / 200` for requests Cedar
refused, and the console reported those as allowed. Every Cedar denial was therefore missing
from the denial count *and* inflating the allowed count.

**Fix at the source, not in the UI.** The RESPONSE interceptor is the only component that sees
both what the interceptor decided and what the caller received, so it stamps `final_status` and
`final_layer` onto the decision record on every response, and into the RESPONSE audit record.

**Attribution with no new field.** A `PENDING#` row is written *only on the allow path*, so its
presence is the signal:

| Pending row | Final status | Conclusion | `final_layer` |
|---|---|---|---|
| present | `>= 400` | the interceptor allowed it; a later layer refused | `403` → `policy_engine`, else `upstream` |
| absent | `>= 400` | the interceptor itself refused | `interceptor` |
| either | `< 400` | dispatched | `none` |

This required making `_write_pending` **unconditional**. It had been gated on
`_charge_state is not None`, so with no budget configured there was no handoff row and no
`decision_pk` to stamp — the mechanism silently did nothing on exactly the deployments that
configure the fewest controls.

Verified live, one denial from each layer plus one success:

```
alice    allowed              200  200  none
bob      model_access_denied  403  403  interceptor
carol    allowed              200  403  policy_engine    CORRECTED
-> 1 allowed, 2 denied, 1 corrected   (was 2 allowed, 1 denied)
```

And in the audit log, from a fresh request after deploy:

```json
{ "status": 403, "final_status": 403, "final_layer": "policy_engine",
  "interceptor_allowed": true,
  "reason": "request was refused by policy_engine; no usage to account" }
```

Rows keep **both** verdicts and are flagged `corrected` when they disagree, so the adjustment is
visible rather than silently applied.

**The general lesson:** if enforcement is layered, no single layer's own record is the outcome.
Something downstream of every layer has to resolve it, and the resolution belongs in the data,
not in each consumer's query — otherwise every new reader of that table reinvents the join, and
some of them get it wrong.

### ⚠️ Normalized keys and request-shaped ids are different namespaces

The admin console's effective-access preview initially evaluated policy globs against the
**pricing table's** `model_key`, which strips punctuation so one row serves every cross-region
variant (`claudeopus5`). The interceptor matches globs against the **request-shaped** model id
(`bedrockprov/anthropic.claude-opus-5`, `us.anthropic.claude-opus-5`).

So `*claude-opus*` never matched, and the preview reported opus as **allowed** for a user who is
in fact denied it — the exact opposite of the truth, which is worse than showing nothing.

Fixed by evaluating only against request-shaped ids: the canonical ids the deployment routes to
(passed from CDK as `GOVERNED_MODEL_IDS`, both surfaces) plus every distinct id observed in real
decision records, so the list tracks actual traffic. Prices are still read from the pricing
table, for display only.

**Rule:** anything that evaluates policy must use the same namespace as the enforcement point.
Never re-derive it from a store that normalizes differently.

### 🔥 STREAMING OPERATIONS WERE SERVED, GOVERNED, AND CHARGED NOTHING (found and fixed)

The most serious accounting bug found so far, and it was invisible because every *control*
worked. Entitlement, guardrail and request-rate all fired correctly. Only the money was wrong.

**Symptom.** A coverage matrix over every surface × operation showed this:

```
/invoke                        alice allowed 200  in=17 out=48   accounted
/converse                      alice allowed 200  in=17 out=48   accounted
/invoke-with-response-stream   alice allowed 200  in= 0 out= 0   NOT accounted
/converse-stream               alice allowed 200  in= 0 out= 0   NOT accounted
```

**Cause, part one — the wrong framing.** Both streaming operations return
`application/vnd.amazon.eventstream`, which is neither JSON nor SSE. The parser handled
buffered JSON and SSE `data:` frames, then fell back to a text regex for `"usage"`. That
regex could never work, because the two event-stream flavours differ:

| Operation | Payload framing | Usage lives in |
|---|---|---|
| `converse-stream` | event JSON directly in the frame | `"usage":{"inputTokens":…}` |
| `invoke-with-response-stream` | `{"bytes":"<base64>"}` per chunk | `amazon-bedrock-invocationMetrics` **inside the base64** |

So for `invoke-with-response-stream` the numbers are not present as text at all. The body was
also being decoded with `errors="replace"` before searching, which corrupts adjacent base64.
Fix: parse from **raw bytes**, extract and decode every `{"bytes":…}` payload, then search
both the frames and the decoded payloads.

**Cause, part two — the refund was on the wrong branch, and this is the part that cost
money.** When usage could not be parsed, the code *released* the reservation:

> release the reservation rather than leaving the caller charged for worst-case output they
> may never have received

That reasoning is correct for a **failed** request and wrong for a `2xx`, where the model ran
and output *was* delivered. Releasing it charged nothing for real generation. Combined with
part one, a caller who always used a streaming operation consumed **unlimited output at zero
recorded spend**, and because token rate limits are corrected from the same reconciliation,
only their prompt counted against TPM.

The rule now, and it is worth stating as a rule:

> **An unmeasurable FAILURE refunds. An unmeasurable SUCCESS keeps the worst-case charge.**

`_release_reservation` became `_settle_reservation(request_id, refund: bool)`. Retaining is
the safe direction: the reservation came from the caller's own declared output ceiling, so it
over-charges at worst and never under-charges. Such rows are marked `usage_estimated=True` so
recorded spend can be told apart from *measured* spend, and the `PENDING#` row is deleted
either way, so a leftover handoff row now always means "in flight" and never "settled".

**⚠️ The test that passed while the parser was broken.** The first parser used
`"usage"\s*:\s*(\{[^{}]*\})`, which forbids nested braces. It passed a synthetic test and
failed on the live payload, because the real `converse-stream` metadata event is:

```
"usage":{"inputTokens":14,"outputTokens":17,"serverToolUsage":{},"totalTokens":31}
```

`serverToolUsage:{}` is a nested object. The synthetic fixture simply did not have that
field — **the test encoded the assumption instead of the payload.** Replaced with a
brace-counting scan (`_json_objects_after`) that handles arbitrary nesting, tracks quoted
strings so a `}` inside a value cannot close early, and cannot backtrack pathologically the
way a nested-quantifier regex can. A **captured live response body** is now a test fixture
alongside the synthetic cases, precisely so the next change is measured against reality.

**What made the diagnosis quick** was adding `_body_preview()`, which reports response
*structure* rather than text — length, leading bytes as hex, and which framing markers are
present. It logged `markers=usage,json_open`, which said immediately that the string was in
the body and the regex was at fault, rather than the data being absent. Structure, not
content, because a response body may contain generated text.

Verified after the fix — all five operations, both surfaces:

```
/v1/messages                   17/48 accounted    (mantle)
/invoke                        17/48 accounted
/converse                      17/48 accounted
/invoke-with-response-stream   17/48 accounted    (was 0/0)
/converse-stream               17/48 accounted    (was 0/0)
```

### ❌→✅ The mirror bug — every denial after the reservation over-charged

Found while fixing the above. The refund logic was on exactly the wrong branch **in both
directions**: the RESPONSE interceptor refunded unmeasurable *successes* (the bypass above),
while nothing refunded *denials* at all. The REQUEST interceptor reserves spend at CONTROL 3
and had **no refund path anywhere**, and the RESPONSE interceptor's `status >= 400` branch
never released either. So every denial after the reservation billed the caller for output
that was never generated:

- a **guardrail** denial (CONTROL 4, after the reserve)
- a **Cedar** denial (the whole interceptor runs first)
- an **upstream** `4xx`
- a **deadline** or dependency failure between the reserve and the return

The worst case was `cost_budget_exceeded`, which charged a user *again* for the request that
told them they were over budget — pushing them further over and lengthening their own
lockout. A spend control that bills you for being denied is not a spend control.

Compounding it, `_write_pending` runs only on the allow path, so on an interceptor denial
there is no `PENDING#` row carrying the reservation details and the response side *cannot*
reverse it. Observed directly: leftover `PENDING#` rows accumulated from denied-after-allow
requests and expired by TTL rather than being settled.

**The fix, and why it is where it is.** The refund lives in **one seam**, `_finish()` inside
`_govern`, which every return already funnels through. Putting it on each deny path was
rejected outright: it would work today and be forgotten the first time someone adds a
control, which is precisely how the original bug happened. A structural test now reads the
AST and fails if any `return` after the reservation bypasses that seam
(`tests/test_cost_symmetry.py`) — the invariant is enforced by the test suite, not by
reviewer attention.

**The raise paths needed a second seam.** `handler` converts anything `_govern` raises into a
typed 403, which skips `_finish` entirely *and* writes no `PENDING#` row — so a failure
between the ledger write and the return stranded the charge with nothing able to reverse it.
`_govern` now clears a shared `reservation` dict once it has either refunded or handed the
charge off, so whatever remains in it at `handler` belongs to an abandoned request, and
`handler` unwinds it.

**This did not weaken fail-closed.** The refund inside `_finish` has no `except`: if the
write fails the exception propagates and becomes a typed 403, so the request is still denied.
The audit record is written *before* `_finish`, so a refund failure cannot erase the reason
for the denial. The refund in `handler` **is** guarded, because it runs inside the except
branches where a raise would discard a precise `governance_timeout` in favour of a bare
gateway 400 — and a guard there cannot turn a deny into an allow, which is the only thing the
invariant actually forbids.

The resulting rule spans both interceptors and is worth stating once:

> **No output produced → refund. Output produced but unmeasurable → keep the worst-case
> charge.**

Verified live against the deployed gateway (`tests/verify_cost_symmetry_live.py`), reading the
ledger counter directly rather than trusting a log line:

```
1. model entitlement (pre-reservation)   403 model_access_denied     $0.005884 -> $0.005884
2. guardrail block (post-reservation)    403 guardrail_intervention  $0.005884 -> $0.005884
3. cost_budget_exceeded x3 retries       429 cost_budget_exceeded    $0.000000 -> $0.000000
4. Cedar denial (post-interceptor)       403 permission_error        $0.000000 -> $0.000000
unsettled PENDING# rows                                              0
```

Scenario 3 is the one that used to be worst: three consecutive denials leave the counter
bit-for-bit unchanged, where previously each retry would have added its own ~$0.006 reservation
and pushed the user further past a budget they had already been refused for.

### ⚠️ Verifying an enforcement decision requires the enforcement point's own precedence

Three traps, all hit while writing that live test, all of which produced a **passing** result
while measuring nothing. Worth more than the fix itself, because they generalise to any test
of a policy-driven control.

**1. The ledger key depends on resolved config, not on the defaults in code.** The bucket is
`int(time) // window`, and `window` comes from the caller's resolved `BUDGET` row. The live
table carries a `GROUP#ai-platform` budget of $50 over **86400s**, so for alice and bob the
interceptor writes to a *daily* bucket. Reading `config.DEMO_COST_WINDOW_SECONDS` (60) meant
reading a row that does not exist — `$0.000000 -> $0.000000`, delta zero, reported PASS. The
test now walks the same `USER# -> GROUP# (token order) -> DEFAULT` chain the interceptor does.
A **non-zero baseline is the tell**: if before and after are both exactly $0.00, suspect the
key before believing the result.

This is the same class of error as the admin console's effective-access preview matching globs
against pricing-table keys instead of request-shaped model ids.

**2. A `USER#` row can silently disable the control you are testing.** The guardrail scenario
originally drove alice, and it returned `200`. Not a regression — a `USER#alice` `GUARDRAIL`
row left over from console testing points at a *different* guardrail with no `PROMPT_ATTACK`
filter. The prompt was correctly evaluated against the policy that actually applied to her.
Any test asserting "this guardrail blocks this prompt" must first confirm which scope the
principal resolves to.

**3. Reconciliation working correctly defeats the obvious way to force a budget denial.**
Burning a budget with a sequential loop does not work, because the RESPONSE interceptor
reconciles each reservation *down* to actual cost before the next request begins. Measured: a
400-token reservation of ~$0.006 settles to ~$0.001, so six calls moved the counter from
$0.006036 to $0.010946 and never reached a $0.02 budget. The fix is to set the budget *below*
one request's reservation, which is the sharper test anyway — every attempt is denied, and
under the old code each denied retry added its reservation permanently, so a user over budget
was pushed further over every time they retried. Three consecutive denials now leave the
counter bit-for-bit unchanged.

### ❌→✅ Cache writes were priced as one line item; there are two tiers

Prompt caching bills **five** distinct quantities, not two: input, output, cache **read**,
and cache **write** at the *5-minute* and *1-hour* TTL tiers. The reconciler priced cache
writes as a single line item at the 5-minute rate, so any request using 1-hour caching was
under-charged by the difference.

The galling part: `_rates()` was already **fetching** `cache_write_1h_per_1k` from the
pricing table, and the caller dropped it on the floor. The pricing sync had parsed the tier
correctly all along (it handles both `CacheWrite1hInputTokenCount` and the newer
`cache_write_tokens_1h` usagetype spellings). The rate was present, correct, and ignored.

Measured on the live pricing table, per 1K tokens — the tiers are not close together:

| model | input | cache read | cache write 5m | cache write 1h |
|---|---|---|---|---|
| `claudesonnet45` | $0.003 | $0.0003 | $0.00375 | **$0.006** |
| `claudeopus5` | $0.005 | $0.0005 | $0.00625 | **$0.01** |
| `claudemythos5` | $0.011 | $0.0011 | $0.01375 | **$0.022** |

So the 1-hour tier is **2.0x input** and **1.6x the 5-minute tier** — a cache-heavy workload
was under-billed by up to 60% of its cache-write line. Of 110 priced models, 24 publish
cache-write rates and 14 publish the 1-hour tier.

Two changes. `_norm_usage()` now splits Anthropic's nested
`cache_creation.{ephemeral_5m_input_tokens, ephemeral_1h_input_tokens}` breakdown into
separate counts instead of reading only the `cache_creation_input_tokens` aggregate. And the
cost math moved into a **pure** `_price_usage(usage, rates)` function, which is what let the
five-quantity arithmetic be unit-tested without DynamoDB — including that the 1h tier prices
strictly above the 5m tier, and that the multiplier fallbacks preserve that ordering
(`read < input < write5m < write1h`) rather than collapsing to zero.

**A missing rate must never mean free.** Every fallback is a multiplier on the input price
(read 0.1x, 5m write 1.25x, 1h write 2.0x — verified exact against the Price List API for
Anthropic). An unknown rate is a measurement gap, and treating a gap as $0 is how tokens get
served for nothing.

**One residual, deliberately recorded on the row.** Converse does not break out the TTL
tiers; it reports only an aggregate. That aggregate is attributed to the 5-minute (cheaper)
tier, so it is the one remaining path that can under-charge. Such records carry
`cache_write_tier_assumed=true`, so assumed spend can be told from measured spend rather
than quietly averaged into it.

**The reservation deliberately does not price cache at all.** Pre-dispatch we cannot know
whether a block will hit or miss the cache, and a cache read is *cheaper* than plain input,
so pricing all input at the full rate keeps the reservation an upper bound — which is what an
enforcement ceiling has to be. Reconciliation is authoritative and is where every tier is
priced. Changing the reservation formula would change enforcement behaviour to buy accuracy
in a place accuracy does not live.

### ⚠️ A TTL under the wrong attribute name is not a TTL

The cost ledger declares `time_to_live_attribute="ttl"`, and DynamoDB reaps items via **that
attribute only**. A timestamp stored under any other name is an ordinary number.

`_check_rate` wrote `expires_at`:

```
RATE#USER#54286468-...#29816726
    attrs=['expires_at', 'pk', 'requests', 'subject', 'tokens']
    ttl=None   expires_at is -722.7 min from now
```

Every other writer in the same file used `ttl` correctly — `DECISION#`, `PENDING#`, `SEEN#`, the
spend counters. Only the rate counters were wrong, and they were never collected. Rows were found
on the live table **12 hours past** their nominal expiry.

**Why it stayed invisible, and why that is the interesting part.** It broke nothing that is read.
The window bucket is part of the counter key (`RATE#<subject>#<bucket>`), so a stale row is never
consulted again — enforcement was correct the entire time. What it did instead:

- **unbounded storage growth** — one row per subject per window, forever. At a 60-second window
  that is 1440 rows per subject per day.
- **inflated every console page load**, because the Statistics tab reads the ledger with a full
  table scan and had to walk all of that dead weight.

So the failure mode was cost and latency creep with no functional symptom, which is exactly the
kind that survives review. It surfaced only because a *different* investigation scanned the table
and the row kinds did not add up.

Two things to carry forward:

- `ttl` is a **DynamoDB reserved word**, so writing it in an update expression needs an
  `ExpressionAttributeNames` alias (`SET #ttl = :e`). That friction is probably what pushed the
  original code toward a different name.
- If a TTL matters, **assert that rows actually disappear**, or at minimum that the attribute
  name matches the table's declaration. "The write succeeded" says nothing about expiry.

Existing rows needed a one-off cleanup — a fixed attribute name does not retroactively expire
anything already written. The cleanup only deleted rows that were both past their nominal expiry
*and* missing `ttl`, so a live counter could not be pulled out from under the interceptor.

### ⚠️ `audit = 1`, not `audit = true`, in Logs Insights

When the admin console gained a deep link into the audit log, the obvious filter was wrong. The
records carry `"audit": true` as a JSON boolean, and CloudWatch Logs Insights surfaces JSON
booleans as `0`/`1`. Measured against the live log group, same query otherwise:

| Filter | Status | Rows |
|---|---|---|
| `filter audit = 1` | Complete | **200** |
| `filter audit = true` | Complete | **0** |

Both *succeed*. The wrong one simply matches nothing — and a prefilled query that opens on an
empty result set tells the reader there is no history, which is worse than shipping no link.

Related, same class of problem: select fields from the stage you are filtering. One request
writes two audit records, and the resolved outcome (`final_status`, `final_layer`) is stamped on
the `RESPONSE` one. Listing those fields alongside `stage = 'REQUEST'` renders empty columns and
implies the outcome was never captured. `request_id` is the join key between the two.

### ⚠️ A write path that validates but does not persist

`RATELIMIT` was added to the admin API's `VALID_KINDS` without a matching branch in the write
path. A `PUT` returned `{"ok": true}` and wrote a row containing only its keys — every attribute
silently dropped. The console then displayed a rate limit that was not being enforced, which is
worse than rejecting the write.

Caught only because the check asserted the **row read back** carried the right value, rather than
asserting the response status. Validate mutations by reading them back.

### Admin console authorization pattern (worth reusing)
No JWT authorizer. The Lambda passes the caller's **access token** to
`cognito-idp:GetUser` — if Cognito accepts it, the token is valid, unexpired and from our
pool, with no hand-rolled JWKS verification — then requires `gateway-admins` membership via
`AdminListGroupsForUser`. This also sidesteps the earlier finding that Cognito access
tokens have no `aud` claim, which makes them awkward for the built-in JWT authorizer.
Verified: no token → 401; valid non-admin token → 401; admin → 200.
Safety: `DEFAULT` rows cannot be deleted (they are the fallback for every principal), and
every mutation logs the acting admin.

---

## CROSS-SURFACE GOVERNANCE (mantle + runtime) — the headline result

### Governance is target-agnostic on inference targets ✅
Full matrix routed through the connector (`bedrock/`) and the provider
(`bedrockprov/`) target gave **identical** results (alice 200/200, bob 200/429,
carol 403, injection 403). No bypass by re-qualifying the model with another target
name. Reason: the rate-limit `qualifiedModelId` dimension resolves to the
**provider-qualified** id (`anthropic.claude-opus-5`), which is target-independent.

### ❌ bedrock-runtime CANNOT be fronted by an INFERENCE target (proven)
Four steps, each with a specific error:
1. **No `bedrock-runtime` connector** — valid ids are only `bedrock-mantle`,
   `openai`, `anthropic`.
2. An inference **provider** target aimed at
   `https://bedrock-runtime.us-east-1.amazonaws.com` gets *remarkably* close:
   model-based routing resolves, `InvokeModel` accepts the **Anthropic Messages body
   verbatim**, and runtime even tolerates the extra top-level `model` field the
   gateway forwards. But every call returns
   `403 "Credential should be scoped to correct service: 'bedrock'."` The gateway
   derives the SigV4 service from the endpoint **hostname** (`bedrock-runtime`),
   while runtime's signing service is **`bedrock`**. Signing the identical request by
   hand with service `bedrock` returns a normal 200 — the defect is only the name.
3. The fix is **rejected**: *"IamCredentialProvider is not supported for this target
   type. Only MCP Server, OpenAPI, and Passthrough targets can configure
   IamCredentialProvider."*
4. Pointing at `bedrock.us-east-1.amazonaws.com` (which *would* derive the right
   service) returns `UnknownOperationException` — it does not serve the invoke API.

### ✅ Runtime works as an HTTP PASSTHROUGH target
`http.passthrough(endpoint=<runtime>, protocol_type="INFERENCE")` +
`GATEWAY_IAM_ROLE` with `credentialProvider.iamCredentialProvider{service:"bedrock",
region:...}`. Passthrough is one of the types permitted to set the signing service,
and `protocolType=INFERENCE` gets a **default Bedrock schema** from the service.
- **Addressed at `<gw>/bedrockrt/model/<modelId>/invoke`**, NOT under `/inference/...`.
  The inference router does not see passthrough targets:
  `"Model 'bedrockrt/...' not found on any target."`
- **Target TYPE is immutable** — `"Target configuration cannot be updated from
  provider to passthrough"` → delete-then-recreate (two deploys; temporarily comment
  the constructor line).
- IAM chain, discovered one 403 at a time (each grant revealed the next):
  * cross-region inference profiles (`us.*`) fan out, so `bedrock:InvokeModel` must
    NOT be region-pinned → `arn:aws:bedrock:*::foundation-model/*` (pinning to
    us-east-1 failed on `us-east-2`).
  * ⚠️ **ENVIRONMENT-DEPENDENT, not universal:** in the account this was built in, runtime
    invocations were subject to an **enforced Bedrock guardrail owned by another project**, so
    the role needed `bedrock:ApplyGuardrail` on **both** `guardrail/*` and `guardrail-profile/*`
    (the latter being a cross-region guardrail profile, `us.guardrail.v1:0`). Granting only
    `guardrail/*` moved the denial on to the profile — the two surface one at a time.

    The general mechanism is the **`bedrock:GuardrailIdentifier` condition key**, which an
    identity policy or SCP can use to deny `InvokeModel` / `Converse` / `InvokeModelWithResponseStream`
    calls that do not carry a mandated guardrail. Because such a policy is written against those
    runtime action names, it does not necessarily cover mantle traffic, which reaches Bedrock via a
    different API surface — which is why the enforcement hit runtime here and not mantle.

    **Do not read this as "mantle never needs ApplyGuardrail and runtime always does."** The split
    is a function of how the controlling policy is scoped in a given org; another account may
    enforce on both, neither, or the opposite one. The stack grants both resource types
    unconditionally: a no-op where no such policy exists, and it prevents an opaque `AccessDenied`
    where one does.

### Which controls reach which surface (measured)

Final state — the two ❌ rows are the mechanisms that were **deleted** as a result:

| Control | Enforced at | mantle (inference target) | runtime (passthrough) |
|---|---|---|---|
| Group authorization | Cedar policy engine | ✅ 403 | ✅ 403 |
| Model entitlement | **interceptor** + config table | ✅ 403 | ✅ 403 |
| Guardrail | **interceptor** → `ApplyGuardrail` | ✅ 403 | ✅ 403 |
| Rate limit (requests + tokens, poolable) | **interceptor** + `RATE#` counters | ✅ 429 | ✅ 429 |
| Cost budget (true spend) | **interceptor** + ledger | ✅ 429 | ✅ 429 |
| Unresolvable model (fail closed) | **interceptor**, CONTROL 0 | ✅ 403 | ✅ 403 |
| Accountability (prompt, response, tools) | both interceptors → audit log | ✅ | ✅ |
| ~~Model entitlement — native `rate:0`~~ | ~~native rate limit~~ | ✅ 429 | ❌ silently passes |
| ~~Per-user TPM — native rate limit~~ | ~~native rate limit~~ | ✅ 429 | ❌ silently passes |

**Root cause of the two ❌:** native token rate limits apply only on known inference
paths (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`). The runtime path is
`/bedrockrt/model/.../invoke`.

### Operation coverage — measured per surface × operation

The claim is that one gateway governs any inference call regardless of backend *and*
regardless of API operation. That was tested rather than assumed, separating two things it is
easy to conflate: **governed** means the interceptor evaluated it and wrote a decision record;
**served** means the target actually dispatched it. Governed-but-not-served is fine.
Served-but-not-governed would be a bypass.

| Surface / operation | Served | Governed | Denial enforced | Cost accounted |
|---|---|---|---|---|
| mantle provider `/v1/messages` | ✅ | ✅ | ✅ | ✅ |
| mantle connector `/v1/messages` | ✅ | ✅ | ✅ | ✅ |
| mantle provider `/v1/chat/completions` | ✖ `400` | ✅ | ✅ | n/a |
| mantle provider `/v1/responses` | ✖ `400` | ✅ | ✅ | n/a |
| runtime `/invoke` | ✅ | ✅ | ✅ | ✅ |
| runtime `/invoke-with-response-stream` | ✅ | ✅ | ✅ | ✅ *(was ❌)* |
| runtime `/converse` | ✅ | ✅ | ✅ | ✅ |
| runtime `/converse-stream` | ✅ | ✅ | ✅ | ✅ *(was ❌)* |

**No bypasses**: nothing is served without being governed. The two `400`s are the provider
target declaring only the Anthropic Messages operation — governed, refused upstream, and
correctly stamped `denied_by_upstream` by the outcome resolver. `bob → opus` was refused on
all eight, on both surfaces.

The two `was ❌` cells are the streaming accounting bug below, which this matrix is what
found. Worth keeping as a regression test: it is the only check that would catch a newly
added operation slipping through ungoverned or unaccounted.

### 🔑 THE LOAD-BEARING CONCLUSION
**Native rate limits cannot carry a cross-surface governance plane** — wrong paths, and they
meter input tokens only so they never bound spend. **The interceptor is the only place uniform
governance can live**: it runs pre-dispatch, sees the JWT *and* the full body on every surface,
and can short-circuit with any status.

Both native rate limits have therefore been **deleted**, not merely demoted. Keeping one as
"defense-in-depth" was the wrong call for two reasons: the depth existed on only one surface, so
it implied a uniformity it did not have; and product intends to consolidate the Bedrock surfaces
onto the runtime endpoint over time, which makes a mantle-only control a dead end rather than a
safety net.

**What replaces it as a backstop** is not another native limit but two structural properties:
the interceptor is **fail closed** (top of this document), and **Cedar** still gates group
membership independently of our code — the one check that cannot time out.

Side effect worth knowing: with native limits gone, the interceptor is the *only* thing that can
return a 429, so identical requests now produce identical statuses on both surfaces by
construction rather than by ordering luck. `bob` on the premium model returns `403
model_access_denied` on both.

### Cost governance (implemented + verified)
Interceptor + DynamoDB ledger (`acgw-pilot-cost-ledger`): estimate prompt tokens
(~4 chars/token; no tokenizer in the Lambda), price via a model-substring map,
`ADD` to a `sub#window` counter with TTL, reject with `429 cost_budget_exceeded` past
budget. **Fails CLOSED** on ledger errors (it used to fail open — see the top of this
document for why that was worse than no error handling at all).
- ✅ Verified on runtime: calls 1-3 allowed, call 4 → `429` with
  `"Spend budget exceeded: $0.0066 of $0.0050"`.
- Ledger accumulates across BOTH surfaces for the same user (log-confirmed charges on
  `bedrock/anthropic.claude-sonnet-5` and `us.anthropic.claude-sonnet-5`).
- With the native TPM limit deleted, nothing masks the cost check on mantle any more, so the
  demo works on either surface. The rate limit is still evaluated *before* the budget, so size
  the two so whichever you mean to show is the one that fires.
- Reserves prompt cost **plus the declared output ceiling**, then the RESPONSE interceptor
  reconciles down to actuals. Charging prompt-only would let a burst of large generations
  overshoot the budget before reconciliation caught up.

### Default serving path
`config.MODELS.inference_model_id` now defaults to the **provider** target
(`bedrockprov/...`). The connector target remains deployed as a comparison artifact.

---

## Inference targets: connector vs provider
- Two flavors: **connector** (zero-config; `connectorId` = `bedrock-mantle` |
  `openai` | `anthropic`) and **provider** (explicit `endpoint` + `operations`
  [path/providerPath/models globs] + `modelMapping`).
- There is **no `bedrock-runtime` connector**; `bedrock-mantle` IS the Bedrock
  connector. Valid connector IDs: `bedrock-mantle`, `openai`, `anthropic`.
- The Bedrock **provider** target is documented: `endpoint
  https://bedrock-mantle.us-east-1.api.aws`, `GATEWAY_IAM_ROLE`,
  `modelMapping.providerPrefix.strip`, operations for `/v1/chat/completions` and
  `/v1/messages` (with `providerPath: /anthropic/v1/messages`).
- ⚠️ **KEY: the connector declares NO input schema.** Cedar/guardrail
  `context.input` is populated from the target's declared schema. So on a
  connector target, `context.input.model` / `.prompt` / `.body` are all
  "not present." This blocks model-based Cedar AND guardrail content evaluation.
  → For anything needing request content in policy, a **provider** target (or an
  interceptor) is required. (Whether the provider target actually surfaces
  `context.input.prompt` is still UNVERIFIED — open question.)

## IAM (gateway execution role)
- bedrock-mantle is a **separate IAM service namespace**. Target creation calls
  `bedrock-mantle:ListModels` (model discovery). Grant AWS-managed
  **`AmazonBedrockMantleInferenceAccess`** (Get*/List*/CreateInference/
  CallWithBearerToken). Plain `bedrock:InvokeModel` is NOT enough.
- Attaching a **policy engine** requires `bedrock-agentcore:GetPolicyEngine` +
  `AuthorizeAction` + `PartiallyAuthorizeActions` on BOTH the policy-engine and
  gateway ARNs (the pre-flight check exercises them on both resource types).
- Guardrails-in-policy needs `bedrock:InvokeGuardrailChecks`.

## Authentication (Cognito)
- ✅ USER_PASSWORD_AUTH, no secret, browser-free. `initiate_auth` UNSIGNED.
- Cognito **access token has no `aud`** (identity in `client_id`, `token_use:
  access`). Authorizer must use **`allowed_clients` only**; setting
  `allowed_audience` → 403 (body misleadingly says `insufficient_scope`; the
  `WWW-Authenticate` header says the truth — trust the header).
- A custom claim into the ACCESS token requires a **pre-token-gen Lambda V2_0** +
  **FeaturePlan.ESSENTIALS**. `InitiateAuth` does NOT emit custom resource-server scopes (so
  this design drops scope-based authz entirely).
  **⚠️ NO LONGER USED.** A `tier` claim was carried this way and has since been deleted; the
  pool runs on `LITE` with no trigger. Governance reads `cognito:groups`, which a standard
  access token already carries, and resolves everything else from the config table. The wider
  lesson is under *Cognito custom attributes are permanent* below.
- **Using Entra ID instead?** The full swap guide — authorizer config, the
  `requestedAccessTokenVersion: 2` issuer mismatch, the bare-client-id `aud`, GUID group claims
  and the groups-overage caveat — is in [`APPENDIX-entra.md`](APPENDIX-entra.md).

## Model routing / IDs
- Client sends `model: "bedrock/anthropic.claude-opus-5"` (target-qualified).
- The rate-limit **`qualifiedModelId` dimension value is different**:
  `anthropic.claude-opus-5` (connector-translated, prefix form) — NOT the
  client-sent string. Verified by trial (wildcard confirmed the dimension
  resolves, then narrowed). Read it from OTEL spans once observability is wired.
- `GET /inference/v1/models` lists routable model IDs (`bedrock/<provider>.<model>`).

## Cedar policy on AgentCore
- Action for an inference target = the **target name** itself (`AgentCore::Action::"bedrock"`),
  resolving at runtime to HTTP-suffixed children `bedrock___POST:/v1/messages` etc.
  A permit scoped to `== "bedrock"` passes validation but does NOT match at
  runtime → use an **unconstrained `action`** in the permit.
- **Deny-by-default flips ON once any policy exists** (with zero policies the
  engine permits). So you need an explicit `permit` + a `forbid` for exceptions.
- **One `CfnPolicy` = one Cedar statement.** permit and forbid are separate policies.
- A constrained action requires a **concrete resource** (the gateway ARN, not the
  `AgentCore::Gateway` type).
- **JWT claims are principal TAGS**, not attributes: `principal.hasTag("cognito:groups")`
  / `getTag(...)`. `cognito:groups` is multi-valued with an opaque representation —
  match with **`like "*group*"`** (`==` and `.contains()` both failed).
- ~~**`context.input.model` NOT available** for the inference action (connector)~~
  **CORRECTED — see "Per-model entitlement IS expressible in Cedar" below.** That test named
  the *parent* action, where no body fields resolve. On the **child HTTP action** the attribute
  is present and enforces. The original note was right about what it tested and was
  over-generalised afterwards into "Cedar cannot do per-model access", which is false on
  mantle and true on the runtime passthrough.

### ✅❌ Per-model entitlement IS expressible in Cedar — on mantle only

Re-tested directly against the live policy engine via `CreatePolicy`, because the earlier
conclusion had been generalised beyond its evidence.

**Method, and why it needed care.** `CreatePolicy` is **asynchronous**: the call returns
success and validation lands later, so the policy goes `CREATING` → `ACTIVE` or
`CREATE_FAILED` with `statusReasons`. A first pass read the create call's return value and
"passed" a policy naming a target that does not exist. Read the terminal status, never the
create response. Note also that `ListPolicies` returns the key `policies`, not `items` — a
cleanup script keyed on `items` silently found nothing and reported success.

The static analyser's breadth findings (`Overly Permissive` / `Overly Restrictive`) fire on
almost any conditioned policy and are noise here, which is why the shipped policies use
`validationMode=IGNORE_ALL_FINDINGS`. But **type errors are still reported even with findings
ignored**, which makes a control pair decisive:

| Probe | Action | Result |
|---|---|---|
| `context.input.model` | `bedrockprov___POST:/v1/messages` | **ACTIVE** |
| `context.input.zzzBogusField` | `bedrockprov___POST:/v1/messages` | `CREATE_FAILED` — *attribute `input.zzzBogusField` in context ... not found* |
| `context.input.model` | `bedrock___POST:/v1/messages` (connector child) | **ACTIVE** |
| `context.input.model` | `bedrockrt` (HTTP passthrough) | `CREATE_FAILED` — *unable to guarantee safety of access to optional attribute `input`* |

The bogus-field control is what makes `ACTIVE` meaningful: the engine really does type-check
the context, so `model` is genuinely in the schema for the mantle child actions.

**Enforcement, not just validation.** A policy that validates and never matches is the worst
outcome, so this was driven with real traffic. With an `ACTIVE` forbid
`when { context.input.model like "*claude-opus*" }` on the provider child action, `alice` — who
is otherwise entitled to opus:

```
surface          baseline   enforced   verdict
mantle sonnet    200        200        unaffected (correct)
mantle opus      200        403        CEDAR ENFORCED
runtime sonnet   200        200        unaffected
runtime opus     200        200        NOT ENFORCED — policy never matched
```

So per-model entitlement in Cedar **works, is enforced, and the glob matches the
request-shaped id** (`*claude-opus*` against `bedrockprov/anthropic.claude-opus-5`).

**❌ Why it does not cover the runtime passthrough.** Two independent reasons:

1. `context.input` is declared **optional** on a passthrough action, so an unguarded reference
   is rejected outright.
2. The guarded Cedar idiom — `when { context has input && context.input has model && ... }` —
   also fails, with a different and more interesting error:

   > `InterceptorException - Received invalid response from interceptor`. The gateway has a
   > dynamic target, so its tools must be listed live from the gateway and that listing failed

   **Validating a policy that names a dynamic (passthrough) target requires a live tool-listing
   round trip through the gateway, and that call goes through the REQUEST interceptor.** Our
   interceptor answers inference-governance verdicts, not MCP tool listings, so it fails the
   listing and the policy cannot be authored at all. Policy authoring and interceptors are
   coupled in a way that is not documented.

Even setting reason 2 aside, the runtime path carries the model in the **URL**
(`/bedrockrt/model/<id>/invoke`), not the body, so `context.input.model` would not be populated
there regardless.

**Consequence for the architecture.** Moving model entitlement to Cedar today would enforce on
mantle and **silently not enforce on runtime** — the exact one-surface trap that caused both
native rate limits to be deleted. So entitlement stays in the interceptor until
`bedrock-runtime` is a first-class inference target with a declared schema, at which point this
should be re-tested and the pivot becomes viable.

Two further properties to weigh even for a mantle-only deployment:

- Cedar policy is **control-plane state, not the config table**. `CreatePolicy` / `UpdatePolicy`
  do exist, so the admin console *could* manage it — but writes are asynchronous and settle in
  roughly 10–40s, versus the config table's ~10s cache with no create-time state machine.
- Cedar cannot express the `USER#` → `GROUP#` → `DEFAULT` resolution the config table gives.
  Per-group entitlement would go back to matching `cognito:groups` with `like "*group*"`, which
  carries the substring weakness recorded below.

### What Cedar governs here: exactly one boolean

Worth stating precisely, because it is easy to overestimate. The deployed policy set is two
statements, and together they compute *may this caller use the gateway at all*:

```cedar
permit(principal is AgentCore::OAuthUser, action,
       resource == AgentCore::Gateway::"<arn>");

forbid(principal is AgentCore::OAuthUser, action,
       resource == AgentCore::Gateway::"<arn>")
unless {
  principal.hasTag("cognito:groups") &&
  principal.getTag("cognito:groups") like "*ai-platform*"
};
```

Cedar does **not** govern which model you may use, how fast, or how much you may spend. Those
are all interceptor controls reading the config table.

The wide `permit` is forced, not sloppy: validation accepts the parent action `bedrock`, but at
runtime the action is the HTTP-suffixed child (`bedrock___POST:/v1/messages`), so a `permit`
scoped `== "bedrock"` matches nothing and the engine reports *no policy applies*. Hence a broad
permit narrowed by a targeted forbid.

**Why keep it, now that the interceptor is the basis of enforcement?** Because Cedar is the only
enforcement path that does not depend on our code or on a Lambda finishing in time — no Python,
no DynamoDB read, no `ApplyGuardrail`, no invocation budget. Given that an interceptor **timeout
fails open** (top of this document), an independent check that *cannot* time out is worth more,
not less. And unlike the native rate limits that were deleted, it applies on **both** surfaces:
verified, a non-member gets `403` on mantle and on the runtime passthrough.

### ⚠️ Two weaknesses in the group gate

**1. Substring matching, not set membership.** `like "*ai-platform*"` is a substring test on an
opaque scalar rendering of a multi-valued claim, so a group named `former-ai-platform-users` or
`no-ai-platform-access` would **also** be admitted. `==` and `.contains()` were tried first and
both proved unreliable against the tag representation, which is how it ended up here.

Risk is negligible in this pilot — three groups, names we control — and the blast radius is
bounded, since passing the gate only gets you to the interceptor, which still decides models,
rate and spend. But it is a genuine authorization defect and **must not be copied into an
environment with a large or externally-managed group directory**. Tightening it means either
finding a reliable exact-match form against the multi-valued tag, or mapping groups to a scalar
claim minted at token issue — which is precisely what the deleted `tier` claim did, and the
reason it existed in the first place.

**2. Cedar denials are attributable, but only by inference.** The interceptor runs *before*
Cedar, so a non-member's request is still recorded `allowed` by the interceptor itself. The
gateway does **not** surface policy-engine decisions to the response interceptor, so the layer is
deduced rather than reported: a `403` on a request the interceptor allowed can only have come
from Cedar on this stack. The RESPONSE interceptor stamps that conclusion as
`final_layer=policy_engine` — see "Resolving the true final outcome" above.

Two caveats on that inference. It relies on Cedar being the only post-interceptor layer that
returns `403`, so adding another would require revisiting it. And a denial's RESPONSE record
carries no `username` (the response event has none), so per-user attribution still comes from
joining `request_id` to the REQUEST record or reading the decision row.

The alternative — duplicating the group check in the interceptor — was rejected: it would defeat
the independence that is the whole reason Cedar is kept.
- Deploy-time **"Overly Restrictive" static analyzer** rejects tag-conditioned
  forbids → set `validation_mode=IGNORE_ALL_FINDINGS`; enforce at runtime.
- Guardrail syntax goes in the CfnPolicy **`policy` field**, not `cedar`.

## Rate limits

> **❌ DELETED FROM THIS STACK — both native rate limits are gone.** Rate limiting lives in the
> REQUEST interceptor (`RATELIMIT` config kind). Everything below remains true about the native
> mechanism and is worth knowing before you rely on it; none of it is deployed here any more.
>
> The tier/model `rate:0` limit went first, because it **contradicted the config table**: an
> admin could allow a model in the console and still see it blocked on mantle by a stale
> rate-limit entry.
>
> The per-user TPM limit on `jwt.sub` was kept for a while as "defense-in-depth on mantle" and
> has now been deleted too. Three reasons it could not be part of a cross-surface plane:
>
> 1. it attaches only on **recognised inference paths**, so the runtime passthrough target was
>    never metered by it at all;
> 2. it meters **input tokens only**, so it cannot bound generation spend;
> 3. it keys on a **scalar claim**, so it can express "500 tokens each" but never "3,000 tokens
>    shared by the ml-research team".
>
> The honest reason for removing rather than keeping it: calling it defense-in-depth flattered
> it, because the depth existed on exactly one surface — a control that looks fully configured
> while enforcing nothing on half the traffic. With the Bedrock surfaces converging on the
> runtime endpoint over time, a mantle-only control is a dead end rather than a safety net.
>
> Verified after removal: `ListGatewayRateLimits` on the gateway returns **0**.

- ✅ Per-user TPM on `$.context.jwt.sub`; ✅ per-model rate:0 on
  `["$.context.jwt.tier", "qualifiedModelId"]` (the tier dimension is gone with the tier axis).
- **Wildcards only in TRAILING dimension positions** → put concrete keys first.
- **Fail open**: an unresolved/mis-valued dimension is silently skipped (looks
  like success but does nothing) — always verify enforced behavior.
- ⚠️ **TOKEN RATE LIMITS METER *INPUT* (PROMPT) TOKENS ONLY — proven.** Decisive
  test against the 200 tokens/min per-user limit: 3 back-to-back calls with tiny
  prompts but `max_tokens=500` produced **1,500 output tokens and were all
  ALLOWED** (cumulative input just 63). Conversely a single ~700-input-token
  prompt returned an immediate `429 {"type":"rate_limit_error","metric":"tokens",
  "limitKey":"<id>","retryAfter":0.3}`. Mechanism: the gateway must admit/reject
  **before** generation, so it can only count what it sees up front (the prompt).
  **Consequence for cost governance:** output tokens usually dominate LLM spend
  (and are priced higher), so a native TPM limit does **not** cap generation cost.
  This materially strengthens the case for the cumulative-cost sidecar below.
  It also means a TPM demo must use a LARGE PROMPT to trigger 429 reliably —
  hammering with many small prompts + big outputs will not trip it.
- **Rate limits are evaluated BEFORE policy** (confirmed): carol (no group, standard
  tier) hitting the premium model returns **429**, not the Cedar **403** — the
  tier rate:0 fires first. Matches AWS's guidance that rate:0 "rejects before
  policy without consuming budget." So a request can be shadowed by whichever
  control sits earliest in the chain; don't assume the 403 you expect.
- AWS explicitly recommends `rate:0` for per-model/role gating (rejects before
  policy without consuming budget).

### ✅ What replaced it: the `RATELIMIT` config kind in the interceptor

Resolved like every other control — `USER#` → `GROUP#` → `DEFAULT` — with attributes
`tokens_per_window`, `requests_per_window`, `window_seconds` and `pooled`. Both dimensions
are enforced; whichever is exhausted first returns `429 rate_limit_exceeded` carrying
`policy_scope`, `pooled`, `tokens_used` and `requests_used` so a caller can act on it.

**Pooling is the capability a native limit cannot express.** The counter key is **the scope
that matched**:

```
pooled     ->  RATE#GROUP#ml-research#<bucket>      one allowance shared by the whole group
not pooled ->  RATE#USER#<sub>#<bucket>             one allowance each
```

A native limit keyed on `jwt.sub` can only ever produce the second form. `pooled` defaults
to true for `GROUP#` scopes and false otherwise, and an admin can override either way.

**Output tokens count.** The request side increments on the prompt estimate; the RESPONSE
interceptor corrects the counter once real output tokens are known. So generation counts
toward the limit instead of escaping it the way an input-only native limit does.

**Fails closed.** One atomic `ADD` per request, and no `try/except` — a counter write that
does not land denies the request. The earlier version returned `{"exceeded": False}` on
error, so a DynamoDB blip silently removed the rate limit while the control looked healthy.

### ⚠️ Fixed window, and the burst-at-boundary is real — it bit the notebook

The window is **fixed**, not sliding: `bucket = now // window_seconds`. Chosen so
enforcement is one atomic `ADD` with a TTL that cleans up after itself; a sliding window
needs either a read-modify-write or a second data store.

The cost is the textbook one, and it is not hypothetical. The notebook's first rate-limit
demo sent **15 small requests against a 10-requests/60s limit and never triggered a 429**,
because each request is a real model round-trip of ~3s, so the burst spanned 42s and
straddled a boundary — the ledger showed two buckets, neither individually over 10.

Generalised: with a fixed window, a client (or an attacker) that spreads requests across a
boundary sees roughly **double** the intended rate for a short period. The demo was changed
to exercise the **token** dimension with a large prompt, which exhausts a 2000-token
allowance in 3 calls inside ~9s — comfortably within one window and therefore deterministic.
If you need a hard guarantee rather than an approximate one, that is the reason to pay for a
sliding window.

## Guardrails on inference
- Docs: guardrails DO run on "HTTP Inference targets — POST /inference" (us-east-1).
  Built-in `BedrockGuardrails::PromptAttack/ContentFilter/SensitiveInformation`
  functions call `InvokeGuardrailChecks` via the role's FAS creds (no provisioned
  Guardrail resource needed). `when guardrails {}` cannot mix with plain `when {}`.
- ❌ **BLOCKED on the connector target:** `context.input.prompt` / `.body` are
  "not present in the context of action bedrock" — no declared schema, no content
  to evaluate.
- ✅ **PROVIDER target DOES surface the request body to `context.input`** (proven).
  Built a 2nd target as an explicit provider (`bedrockprov`, endpoint
  `https://bedrock-mantle.us-east-1.api.aws`, op `/v1/messages`). Guardrail must
  be scoped to the **CHILD HTTP action** `"<target>___POST:/v1/messages"` (NOT the
  bare parent target name — the parent declares no body fields). With that scope:
  - `context.input.messages` **resolves**, typed **`Set<record>`**.
  - `context.input.system` **resolves**, typed **`record`**.
  - `context.input.messages.content` → "not present" (Cedar does NOT auto-flatten
    into array elements; only declared top-level fields resolve).
- ❌ **But `PromptAttack`/guardrail data-path args require a scalar `string`.** The
  Anthropic Messages body has NO flat top-level string field — the prompt text is
  nested in `messages[].content[].text` (a `Set<record>`), unreachable by a scalar
  dot-path. Deploy error is explicit: *"argument `context.input.messages` has type
  `Set<record>` ... but the provider declares argument type `string`."* So the
  guardrail can SEE the body but can't EXTRACT the prompt string from the
  structured Messages schema. (The doc's clean examples — `context.input.message`,
  `context.input.systemPrompt`, `context.input.description` — assume a FLAT string
  field, which the OpenAI/Anthropic message-array bodies don't have.)
- **Conclusion:** native guardrail-in-policy works for targets whose operation
  schema has a flat string prompt field; it does NOT work for the
  chat/messages array-body inference operations.
- ✅ **SOLVED via a REQUEST interceptor Lambda — proven end-to-end.** A gateway
  REQUEST interceptor (`acgw-pilot-guardrail-interceptor`) receives the raw base64
  request body, flattens the caller's prompt text out of `messages[]`/`system`
  (trivial in Python — the exact step Cedar's scalar data-path could not do),
  calls Bedrock **`ApplyGuardrail`** (the stack's guardrail, PROMPT_ATTACK HIGH
  + HATE/VIOLENCE), and on `GUARDRAIL_INTERVENED` **short-circuits** by returning
  a `transformedGatewayResponse` (HTTP 403) — Bedrock is never called. VERIFIED:
  benign prompts → 200 (incl. "cooking *instructions*" → 200, so it's ML scoring
  not keyword matching); two different prompt-injection phrasings → 403. Logs show
  `action=NONE` vs `action=GUARDRAIL_INTERVENED` per request.
- **Interceptor wiring gotchas (both required):** (1) the interceptor Lambda
  needs a resource policy allowing `bedrock-agentcore.amazonaws.com` to invoke it
  (source_arn = gateway ARN); (2) **the GATEWAY EXECUTION ROLE also needs
  `lambda:InvokeFunction`** on the interceptor — the gateway invokes it under its
  own identity. Missing (2) → `400 "Access denied while invoking Lambda function
  ... Check the permissions on the Lambda function and Gateway execution role"`.
- **Interceptor payload for inference = the HTTP shape** (`event["http"]`, NOT
  `event["mcp"]`); body is **base64**. Confirmed at runtime: `keys=
  ['interceptorInputVersion','http']`. Docs: *"inference targets ... share the HTTP
  interceptor payload shape."* `passRequestHeaders=True` surfaces the inbound JWT
  to the interceptor (per-user attribution / claim-scoped guardrails).
- ✅ **STREAMING IS PRESERVED with a REQUEST-only interceptor — VERIFIED.** This is
  the important architectural result. The docs' blanket line (*"Interceptors are
  not yet supported in streaming mode"*) reads as if any interceptor kills
  streaming; empirically it applies to **RESPONSE** interception only. With
  `interception_points=["REQUEST"]` and `stream: true`:
  - `Content-Type: text/event-stream; charset=utf-8`, `Transfer-Encoding: chunked`
  - 380 SSE events / **185 incremental `text_delta` chunks**, first event at 2.20s,
    last at 10.75s → **8.55s spread of progressive delivery** (genuine
    token-by-token streaming, not a buffered response replayed as SSE).
  - An injection prompt with `stream: true` → **403 before the stream opens**,
    returned as clean `application/json` (not a half-open event stream). Because
    the block is pre-dispatch, clients get a proper error instead of having to
    unwind a partial stream.
  **Mechanism:** a REQUEST interceptor completes before the gateway dispatches and
  only touches the request body — it never sits in the response path, so there is
  nothing to buffer.
- **Asymmetric enforcement (the design lever):**
  | Enforcement point | Streaming | Enforceable |
  |---|---|---|
  | REQUEST interceptor | ✅ preserved | prompt injection, input content filters, prompt PII, per-claim input rules |
  | RESPONSE interceptor | ❌ forces buffering | output moderation, response PII redaction |
  So **input-side governance is effectively free** (keep streaming; pay only
  pre-dispatch interceptor latency), while output-side moderation is a deliberate
  per-use-case tradeoff. For a governed front door this means prompt-injection and
  input-PII controls can be mandated org-wide without degrading streaming clients.
  (NOT yet measured: exactly how a RESPONSE interceptor degrades streaming — docs
  say buffered; untested here.) Also note the Lambda sync payload cap of 6 MB
  (combined) — large responses need a payload filter excluding `RESPONSE_BODY`.
- Per-event streaming interception (`isStreamingResponse`, one Lambda invoke per
  event) exists **only for MCP targets**, not inference/HTTP.

## Observability — WIRED ✅ (with one important gap)

### How to wire it (two layers; only the second belongs in the stack)
1. **Account-level: CloudWatch Transaction Search must be ON.** X-Ray trace segment
   destination = `CloudWatchLogs`, plus a logs resource policy letting
   `xray.amazonaws.com` `PutLogEvents` to `aws/spans` +
   `/aws/application-signals/data`. Enable once per account:
   `aws xray update-trace-segment-destination --destination CloudWatchLogs`.
   **Gateway tracing cannot be enabled until this is done.** Deliberately NOT in
   the stack — it is an account-wide setting with its own ingestion cost.
   (On this account it was already ACTIVE.)
2. **Per-gateway: vended log delivery** (in `foundation_stack._build_observability`).
   Two `CfnDeliverySource` on the gateway ARN (`APPLICATION_LOGS` + `TRACES`), two
   `CfnDeliveryDestination` (`CWL` → a `/aws/vendedlogs/...` log group for logs;
   `XRAY` with **no** `destination_resource_arn` for spans), and a `CfnDelivery`
   joining each pair. Log group name **must** be under `/aws/vendedlogs/` or the CWL
   destination isn't writable without an extra resource policy.
- ✅ VERIFIED: 6 varied requests → exactly 6 `AgentCore.Gateway.InvokeHttp` spans in
  `aws/spans`, ~1–2 min delivery lag. (`storedBytes` on the log group lags further;
  don't trust it as a signal — query the spans.)

### What gateway spans DO give you (verified attribute values)
- `http.response.status_code` (200/403/429), `http.method`, `url.path`
- `errorType`: **`throttle`** (429) vs **`user`** (403) vs absent (200) — i.e. you can
  tell *which layer* rejected a request, the single most useful governance signal.
- `aws.agentcore.gateway.throttle.customer.decision` = `throttled`
- `...throttle.customer.limit_key` — **which rate limit fired** (`a5vc3bwy6o` per-user
  TPM vs `dpaamtwrgh` tier/model)
- `...throttle.customer.matched_entry` — **the dimension values that matched**, e.g.
  `"standard,anthropic.claude-opus-5"`. **This solves the earlier trial-and-error
  hunt for `qualifiedModelId`** — the span tells you the exact value the gateway used.
- `...throttle.customer.evaluated` — ordered list of buckets checked, e.g.
  `["dpaamtwrgh:tokens:standard,anthropic.claude-opus-5"]`
- `...throttle.customer.metric` (`tokens`), `aws.agentcore.gateway.policy.mode`
  (`ENFORCE`), `gateway.id`, `gateway.name`, `aws.request.id`, `aws.resource.arn`
- `resource.attributes`: `cloud.resource_id` = gateway ARN, `service.name` = gateway id

### ❌ The gap: spans carry NO end-user identity and NO token usage
Searched every attribute across all spans for `jwt` / `sub` / `user` / `principal` /
`tier` / `claim` → **NONE**. Same for `model` / `token` / `usage` → **NONE**.
- **Per-user attribution is NOT available from gateway spans.** Worse, a **wildcard
  rate-limit entry masks the value**: the per-user TPM limit reports
  `matched_entry: "*"`, not alice's actual `sub`. So even the dimension that *is*
  keyed on identity doesn't reveal identity in telemetry.
- **No token counts in spans**, so **a cost ledger cannot be built from spans alone.**
- **Implication for usage recording — since DELIVERED exactly this way:** the recorder had
  to be the **interceptor**, not spans. The REQUEST interceptor receives the JWT (via
  `pass_request_headers=True`) *and* the request body (model + prompt), so it emits
  per-user usage; output tokens required a RESPONSE interceptor, which costs streaming.
  Both are now built (see *TRUE-COST ACCOUNTING* above), and both also write to the
  **central audit log**, which retains identity, tokens and true cost for 90 days —
  the durable answer to everything spans cannot tell you.
- Bedrock's own logs/CloudTrail remain useless for attribution: the gateway signs
  every call with ONE shared execution role.

### Useful query
```
fields @timestamp, attributes.`http.response.status_code` as status,
       attributes.errorType as layer,
       attributes.`aws.agentcore.gateway.throttle.customer.limit_key` as limit_key,
       attributes.`aws.agentcore.gateway.throttle.customer.matched_entry` as matched
| filter attributes.`gateway.id` = "<gateway-id>"
| sort @timestamp desc
```

## Clients
- ✅ Any base-URL + bearer client (curl, OpenAI SDK, Anthropic SDK).
- ❌ **Claude Code**: sends `authorization` + `x-api-key` together → gateway
  returns `401 request must not include both`. No env fix. Documented non-goal.
- boto3 `InvokeModel` is NOT the path (this is an LLM-provider REST API).

## ❌ SUPERSEDED DESIGN: the cost "sidecar" (recorded so it is not re-attempted)

The original plan for cumulative-cost budgets was a **sidecar**: read usage from spans →
accumulate in a DynamoDB ledger → call `UpdateGatewayRateLimit` to set `rate:0` when a
budget is exceeded, with ~30s propagation and a soft threshold around 90%.

**Every step of that turned out to be wrong**, and each failure is documented above:

| Sidecar step | Why it does not work |
|---|---|
| Read usage from spans | Spans carry **no token counts and no identity** — see the gap directly above. |
| Enforce by setting `rate:0` | Native rate limits **never fire on the runtime passthrough path**, so half the traffic is uncapped. |
| Enforce by setting `rate:0` | It also **contradicted the config table**: an admin could allow a model in the console while a stale `rate:0` still blocked it. The limit was deleted for this reason. |
| ~30s propagation | Enforcement lagging by ~30s is unbounded overspend at LLM prices. |

**What replaced it.** The REQUEST interceptor *reserves* worst-case output cost from the declared
output ceiling before dispatch and the RESPONSE interceptor reconciles to actual usage, both
against a DynamoDB ledger. That works identically on both surfaces, enforces synchronously rather
than after a propagation delay, and keeps a single source of truth. **Native rate limits are not
retained at all** — see *Rate limits*.

The deeper lesson from this dead end: the sidecar design assumed the *native* controls were the
enforcement point and something else could steer them. Every failure above traces back to that
assumption. Once the interceptor became the enforcement point, all four problems dissolved.

The general lesson: **do not build a control loop on telemetry that lacks the fields the
control needs**, and do not enforce through a mechanism whose coverage is narrower than the
surface you are governing.

---

# What to know before you rely on this

Everything above is organised by *what we learned building it*. This closing section is
organised by *what will affect you if you deploy it*, and it is what the README links to.
Split by whether it is an AWS service constraint or this demo's choice.

## AWS service constraints — you will hit these too

| Constraint | Consequence | Detail |
|---|---|---|
| **A REQUEST-interceptor timeout makes the gateway fail OPEN** | `200` with the model invoked and no governance applied. Throttling and unhandled exceptions fail *closed* (`400`), so the failure most likely in production is the unsafe one — and there is no configuration knob. Any interceptor-based governance must enforce its own deadline. | *top of this doc* |
| **The gateway may retry an interceptor Lambda** | AWS documents this and asks for idempotent handlers. Any `ADD`-style counter or ledger write double-counts on retry. | same section |
| **bedrock-runtime cannot be fronted by an inference target** | The gateway derives the SigV4 service from the endpoint hostname (`bedrock-runtime`) but runtime signs as `bedrock`, and the `IamCredentialProvider` override is rejected on inference targets. Hence an HTTP **passthrough** target, addressed at `/bedrockrt/model/<id>/<verb>` rather than under `/inference/...`. | *Cross-surface governance* |
| **Native rate limits cover only recognised inference paths** | They never metered the passthrough target, they count input tokens only, and they key on a scalar claim so a shared team allowance is inexpressible. Both are deleted here. | *Rate limits* |
| **Cedar cannot see the requested model** | Per-model entitlement is impossible in policy. It also renders multi-valued `cognito:groups` as an opaque scalar, so membership must be matched with `like "*group*"` — a **substring** test that a group name merely *containing* the string would satisfy. `==` and `.contains()` both proved unreliable. | *Cedar policy on AgentCore* |
| **Guardrail data paths require a scalar string** | Native guardrail-in-policy cannot read chat-style bodies, because prompt text is nested in `messages[].content[]` (typed `Set<record>`). A provider target *does* expose the body, but the scalar constraint still blocks extraction. | *Guardrails on inference* |
| **Response interception is buffered and not tunable** | For HTTP/inference targets AWS supports response interceptors "in buffered mode (not yet supported in streaming mode)". Per-event interception exists only for MCP gateways. Enabling true output-token cost therefore costs progressive streaming — measured, first token 2.7s → 7.4s and a 5.4s spread → 0.0s. | *Interceptor buffering is NOT tunable* |
| **Lambda synchronous invocation caps request + response at 6 MB** | A large base64 inference body can exceed it. The documented escape — a payload filter excluding `RESPONSE_BODY` — removes the very field output-token accounting reads. | same section |
| **Gateway spans carry no identity and no token counts** | And interceptor short-circuits are not spanned at all. Measured: 10 interceptor decisions including 6 denials, against spans showing a single `403`. Span-derived denial counts undercount badly. | *Observability* |
| **Cross-region inference profiles cannot be region-pinned** | The `us.*` profiles fan out, so `bedrock:InvokeModel` scoped to one region fails naming a *different* region's ARN. | *IAM* |
| **Cognito custom attributes are permanent** | `Existing schema attributes cannot be modified or deleted`, and renaming the pool does not replace it. Removing one costs a **replacement user pool**. | *Authentication* |
| **The Price List API splits Bedrock across two service codes** | Different schemas, different units (per-1K vs per-1M), and mid-migration between two `usagetype` conventions. Handling only the obvious source, or only the older convention, yields no price for current-generation models. | *Model pricing is runtime state* |
| **Your org's policies may add requirements this stack cannot see** | An account or SCP can *require* a guardrail via the `bedrock:GuardrailIdentifier` condition key, which then demands `bedrock:ApplyGuardrail` on the caller — including on `guardrail-profile/*` if the mandated guardrail is a cross-region profile. Because such a policy is written against *runtime* action names it may not catch mantle traffic, so the surfaces can behave differently. **That split depends on your policy, not on the surfaces.** | *IAM* |
| **Undocumented: the RESPONSE interceptor *does* run after a REQUEST short-circuit** | AWS states that for HTTP targets it does not. Measured here, it does. Do not rely on either behaviour without testing it. | *Docs contradiction* |

## Demo-grade by choice

These are decisions, not discoveries. Each is a deliberate trade for a demonstration and each
is a known edit if you want the other side of it.

- **Fail-closed means a governance outage is an inference outage.** That is the intended
  posture; the mitigation is the break-glass config row rather than a softer default. If you
  would rather trade enforcement for availability that is a one-row change — but make it
  deliberately, and know the gateway will not fail closed for you on a timeout.
- **One allow survives without a content verdict.** A *recognised* request shape carrying
  genuinely no caller text (an image-only turn) is allowed and recorded, because there is
  nothing for a prompt guardrail to evaluate and denying would break legitimate traffic. An
  *unrecognised* shape with no text is denied `unrecognised_shape`.
- **Retry idempotency assumes a stable `REQUEST_ID` across gateway retries.** Unverified — the
  API offers no way to induce a retry — so treat it as defence, not a guarantee.
- **A Cedar denial is attributed by deduction, not by report.** The gateway never tells the
  response interceptor that the policy engine denied; the layer is inferred from "the interceptor
  allowed this and the caller got a `403`". Sound here because Cedar is the only post-interceptor
  layer returning `403`, but it is an assumption about the stack, not a fact from the gateway.
  A denial's RESPONSE record also carries no `username` — join on `request_id` for that. And the
  interceptor still charges cost for requests Cedar then denies, since it runs first.
- ⚠️ **A user in several groups resolves policy by claim order, not by priority.** Only the
  first matching `GROUP#` row is evaluated per kind, and the group ordering comes from the
  access token — measured to be neither the declaration order nor ascending `precedence`. It is
  latent while one group carries a row of any given kind, and it does **not** behave as "most
  restrictive wins". This is the first thing to address before using this against a real
  directory; see the multi-group future-enhancement section above.
- **Rate limits and budgets use fixed windows**, so a burst straddling a boundary can briefly
  exceed the intended rate. See the burst-at-boundary note under *Rate limits*.
- **Cost is reconciled after the fact**, so a burst can momentarily exceed a budget. Reserving
  from the caller's declared output ceiling bounds this; it does not eliminate it.
- **Prompt-token estimation is approximate** (~4 chars/token; there is no tokenizer in the
  Lambda). It affects only the *reservation* — recorded spend is reconciled against reported
  usage.
- **The reservation deliberately does not price prompt caching.** Pre-dispatch it is unknowable
  whether a block will hit or miss the cache, and a cache read is cheaper than plain input, so
  charging all input at the full rate keeps the reservation an upper bound — which is what an
  enforcement ceiling has to be. Cache tiers are priced during reconciliation, which is
  authoritative.
- **Cache-write TTL tiers are only measurable where the provider reports them.** Anthropic
  breaks out 5-minute and 1-hour writes and both are priced at their published rates; Converse
  reports one aggregate, which is attributed to the cheaper 5-minute tier. Those records carry
  `cache_write_tier_assumed=true`, so assumed spend can be told apart from measured spend.
- **A denied request costs nothing, but only after the fact on two paths.** Interceptor denials
  refund inline; Cedar denials and upstream `4xx` are reversed by the RESPONSE interceptor, so
  the counter is briefly high between the two. Enforcement therefore errs toward denying early,
  never toward allowing.
- **Budgets do not pool the way rate limits do.** A `GROUP#` budget currently applies per
  member.
- **Policy changes are eventually consistent**, bounded by the config cache TTL (~10s). Seeding
  is create-only, so redeploys never overwrite runtime edits — which also means changing a seed
  value in code has no effect on an existing table.
- **Demo-grade identity.** Four demo users whose passwords are generated at deploy time (or
  set via `ACGW_DEMO_PASSWORD` / `ACGW_ADMIN_PASSWORD`) and exposed as stack outputs rather
  than hardcoded, the console uses the password flow rather than the hosted UI with PKCE, and
  the pool is destroyed with the stack.
- **Prompt and response text are not logged by default** — only SHA-256 and length. A
  CloudWatch data protection policy masks 8 identifier types at ingest, which is what makes
  opting in defensible.
- **The audit log holds personal data** — `username`, the Cognito `sub`, group membership and
  the caller `source_ip`, retained 90 days. That is deliberate (it is what makes the trail
  useful for security review) but it makes the log in-scope for privacy law. An operator
  running this for real, especially with EU/UK callers, must confirm a lawful basis, record the
  processing (GDPR Art. 30), review the retention against data-minimization, and decide whether
  `source_ip` is needed at all. The sample makes no compliance claim; see
  [`ADMIN-CONSOLE.md`](ADMIN-CONSOLE.md) *Relationship to the central audit log* and the AWS
  [GDPR Center](https://aws.amazon.com/compliance/gdpr-center/).
- **The admin console has no CloudFront or WAF in front of it**, CORS is `*`, there is no
  optimistic concurrency on policy edits, and its statistics read the 24-hour decision records
  rather than the 90-day audit log — it links out to Logs Insights for anything older. All
  tracked in [`ADMIN-CONSOLE.md`](ADMIN-CONSOLE.md).

## The three lessons that generalise

1. **Native rate limits cannot carry a cross-surface governance plane.** They attach only on
   recognised inference paths and meter input tokens only. Half a control is worse than none,
   because it reads as coverage.
2. **A control that reads the request body inherits every body format the front door accepts.**
   Three separate bypasses came from per-shape field lookups. Enumerate the shapes, harvest
   structurally, and make the unparsed case fail closed.
3. **Concentrating enforcement in one place makes its failure modes load-bearing.** Test the
   failure paths, not just the deny paths — and remember that `except: return _passthrough()`
   can be worse than no error handling at all.
