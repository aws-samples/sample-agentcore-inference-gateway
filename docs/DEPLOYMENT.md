# Deploying this into your own account

Everything here is provisioned by CDK, including the identity provider. There is nothing to
create by hand and no external tenant to register. Clone, deploy, run the notebook.

Commands are PowerShell (Windows). On macOS/Linux use `.venv/bin/python` in place of
`.\.venv\Scripts\python.exe` and `source .venv/bin/activate`; nothing else differs.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| An AWS account you can deploy into | Not a shared/production account. This creates a user pool with demo passwords. |
| Credentials on the CLI | `aws sts get-caller-identity` must succeed. SSO, profile or keys all work. |
| **Bedrock model access enabled** | The single most common failure. See step 2. |
| CDK bootstrapped in the target account+region | `npx cdk bootstrap aws://<account>/<region>` if you have never used CDK there. |
| Python 3.12+ | 3.12 is what this was built and verified on. |
| Node.js 18+ | Only to run the CDK CLI via `npx`. No JavaScript in this repo. |

Permissions: deployment creates IAM roles, so you need administrative or equivalently broad
permissions. This is not a least-privilege-deployer sample.

### Region

Verified end to end in **us-east-1**. The region is not hardcoded — it is taken from your
ambient AWS configuration (see step 3) — but two things are genuinely region-dependent:

- **bedrock-mantle** must be available in your region, at `bedrock-mantle.<region>.api.aws`.
- The **cross-region inference profiles** used on the runtime surface are prefixed `us.*`, which
  is a US-region construct. In an EU or APAC region you would need the matching prefix.

If you are evaluating this for the first time, use us-east-1.

## 2. Enable Bedrock model access

The pilot invokes two Anthropic models. Both must be enabled in the Bedrock console under
**Model access** before any inference call will succeed:

| Role in the demo | mantle model id | runtime inference profile |
|---|---|---|
| base model | `anthropic.claude-sonnet-5` | `us.anthropic.claude-sonnet-5` |
| premium model (denied at `DEFAULT`, allowed for `GROUP#ml-research`) | `anthropic.claude-opus-5` | `us.anthropic.claude-opus-5` |

Confirm from the CLI that your account can see them:

```powershell
aws bedrock list-foundation-models --by-provider anthropic `
  --query "modelSummaries[?contains(modelId,'claude-sonnet-5')||contains(modelId,'claude-opus-5')].modelId"

aws bedrock list-inference-profiles `
  --query "inferenceProfileSummaries[?starts_with(inferenceProfileId,'us.anthropic.claude-sonnet-5')].inferenceProfileId"
```

**Using different models?** Change `MODELS` in `pilot/config.py` — `inference_model_id`,
`premium_model_id`, `runtime_base_model`, `runtime_premium_model` — and add matching entries to
`MODEL_INPUT_PRICES_PER_1K` / `MODEL_OUTPUT_PRICES_PER_1K`, which are matched by substring.
Non-Anthropic model families use a different request body and a different inference path, so
they need a matching change in the provider target operation too.

## 3. Target account and region

`pilot/config.py` resolves these from the environment, in this order:

1. `ACGW_ACCOUNT` / `ACGW_REGION` — explicit override
2. `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION` — set automatically by the CDK CLI from your credentials
3. your boto3 session — so a bare `python app.py` also works

So the normal case needs no configuration at all. To pin it explicitly:

```powershell
$env:ACGW_ACCOUNT = "111122223333"
$env:ACGW_REGION  = "us-east-1"
```

These values are needed at **synth** time, because IAM resource ARNs and the Cognito discovery
URL are built as real strings rather than CloudFormation tokens. If neither the environment nor
your credentials resolve, synth fails with a message telling you which to set.

## 4. Install

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Use the venv interpreter explicitly, as above, or activate first with
`.\.venv\Scripts\Activate.ps1`. `cdk.json` already points the CDK CLI at
`.venv\Scripts\python.exe`, so the CDK CLI picks up the venv without activation.

Sanity check before deploying anything:

```powershell
npx cdk synth AcgwPilotFoundationStack
```

First synth takes a few minutes while the jsii bridge starts. It should end with a template on
stdout and no annotations.

## 5. Deploy

```powershell
npx cdk deploy AcgwPilotFoundationStack --require-approval never
```

About 5–8 minutes. It creates one stack containing roughly 60 resources: the gateway and its
execution role, three inference/passthrough targets, a Cognito user pool with demo users, a
Cedar policy engine and policies, a Bedrock guardrail, four DynamoDB tables (governance
config, cost ledger, model pricing, cost rollup), five Lambdas (two interceptors, admin API,
pricing sync, cost rollup), the admin console (CloudFront + private S3 + API Gateway), two
EventBridge schedules, and vended log delivery. Around 90 resources in total, including the
CDK-managed helpers for the S3 deployment.

Everything is named `acgw-pilot-*`. If you already run other AgentCore gateways in the account,
check for collisions first with `aws bedrock-agentcore-control list-gateways`.

### What you get

```powershell
aws cloudformation describe-stacks --stack-name AcgwPilotFoundationStack `
  --query "Stacks[0].Outputs[].{Key:OutputKey,Value:OutputValue}" --output table
```

| Output | Use |
|---|---|
| `GatewayUrl` | base inference URL; clients use `<GatewayUrl>/inference/v1` |
| `UserPoolId`, `UserPoolClientId` | Cognito login |
| `AdminConsoleUrl` | governance console (the CloudFront domain) |
| `GovernanceConfigTable` | policy table the interceptor reads |
| `ModelPricingTable`, `CostRollupTable` | live prices; per-user daily/monthly cost history |
| `AuditLogGroupName` | the single governance audit log (see below) |
| `GuardrailId`, `GatewayLogGroupName` | guardrail and gateway logs |

You do not need to copy any of these into code. The notebook calls `ic.discover()`, which reads
the stack outputs and re-points the client at your deployment.

### Demo identities

Created by the stack. Passwords are **not hardcoded** — set `ACGW_DEMO_PASSWORD` (inference
users) and `ACGW_ADMIN_PASSWORD` (admin) before deploying for known values, or leave them
unset and a random password is generated per deploy. Either way, retrieve the values from the
stack outputs:

```powershell
aws cloudformation describe-stacks --stack-name AcgwPilotFoundationStack `
  --query "Stacks[0].Outputs[?OutputKey=='DemoUserPassword'||OutputKey=='AdminUserPassword'].{Key:OutputKey,Value:OutputValue}" --output table
```

| User | Password (stack output) | Groups | Purpose |
|---|---|---|---|
| `alice` | `DemoUserPassword` | `ai-platform`, `ml-research` | allowed everywhere; her `ml-research` membership grants the premium model and a **pooled** rate allowance |
| `bob` | `DemoUserPassword` | `ai-platform` | allowed in, blocked from the premium model by the `DEFAULT` scope |
| `carol` | `DemoUserPassword` | *(none)* | denied entry by Cedar |
| `gwadmin` | `AdminUserPassword` | `gateway-admins` | admin console only, no inference access |

The notebook and client read the demo password from `pilot/config.py` in-process, so they work
without you copying it anywhere; only the manual admin-console login needs the value above.

There is no tier. Group membership is the only identity axis; everything else resolves from the
governance config table at request time.

## 6. Run the walkthrough

```powershell
.\.venv\Scripts\python.exe -m jupyter lab walkthrough.ipynb
```

Select the `.venv` kernel, then run top to bottom. The first cell discovers your stack; every
later cell is a live call against your gateway. Expect the demo matrix to reproduce exactly:

| | base model | premium model |
|---|---|---|
| `alice` | `200` | `200` |
| `bob` | `200` | `403` |
| `carol` | `403` | `403` |

No notebook? A one-shot smoke test:

```powershell
.\.venv\Scripts\python.exe -m pilot.inference_client
```

Note that `get_token` and `invoke` need **no AWS credentials** — only a bearer token. Only
`discover()` reads CloudFormation.

## 7. Open the admin console

```powershell
aws cloudformation describe-stacks --stack-name AcgwPilotFoundationStack `
  --query "Stacks[0].Outputs[?OutputKey=='AdminConsoleUrl'].OutputValue" --output text
```

Sign in as `gwadmin` with the `AdminUserPassword` stack output (see *Demo identities* above).
Change a model-access glob or a budget, then re-run a
notebook cell: enforcement follows within the config cache TTL (~10s), with no redeploy.
Internals in [`ADMIN-CONSOLE.md`](ADMIN-CONSOLE.md).

## 8. Search the audit log

Every governance decision and guardrail intervention lands in one CloudWatch log group,
`/acgw-pilot/governance-audit`, written by both interceptors. Records are single-line JSON tagged
`audit: true`, with the REQUEST and RESPONSE halves of a call joined on `request_id`.

Every governed request, most recent first:

```
fields @timestamp, stage, username, groups, surface, api_shape, model, decision, status
| filter audit = 1
| sort @timestamp desc
| limit 50
```

The one query to run before you trust the deployment — it should return **nothing**:

```
fields @timestamp, decision, control, reason, remaining_ms
| filter audit = 1
| filter decision in ["governance_timeout", "governance_unavailable", "breakglass_bypass"]
| sort @timestamp desc
```

Those three mean governance could not be applied or was deliberately switched off, as opposed to
a user hitting policy. Anything here is an operational signal, not normal traffic.

Every guardrail intervention — the query a security reviewer actually wants:

```
fields @timestamp, username, surface, api_shape, model, guardrail_policies, prompt_sha256
| filter audit = 1 and decision = "guardrail_blocked"
| sort @timestamp desc
```

Anything that failed open, i.e. was allowed without a guardrail verdict:

```
fields @timestamp, username, api_shape, decision, guardrail_skip_reason
| filter audit = 1 and fail_open = 1
| sort @timestamp desc
```

True spend per user over the window:

```
fields username, cost_usd
| filter audit = 1 and stage = "RESPONSE" and ispresent(cost_usd)
| stats sum(cost_usd) as usd, count(*) as calls by username
| sort usd desc
```

From the CLI:

```powershell
aws logs start-query --log-group-name /acgw-pilot/governance-audit `
  --start-time (([DateTimeOffset]::UtcNow.AddHours(-1)).ToUnixTimeSeconds()) `
  --end-time (([DateTimeOffset]::UtcNow).ToUnixTimeSeconds()) `
  --query-string 'fields @timestamp, username, decision, status | filter audit = 1 | sort @timestamp desc'
```

Two things to know:

- **Logs Insights lags ingestion.** Immediately after driving traffic, a query can return a subset
  while the rest is still being indexed. Wait a minute or two, or read the stream directly with
  `aws logs get-log-events`, which is immediate.
- **Prompt text is not recorded by default.** Records carry `prompt_sha256` and `prompt_chars`
  instead. Set `AUDIT_LOG_PROMPT_TEXT = True` in `pilot/config.py` only if you accept prompt
  content in CloudWatch Logs; `AUDIT_LOG_PROMPT_MAX_CHARS` truncates each unit.

Retention defaults to 90 days (`AUDIT_LOG_RETENTION`, a CloudWatch `RetentionDays` member name).
The DynamoDB decision records, by contrast, TTL out after 24 hours (`DECISION_RECORD_TTL_SECONDS`)
— they are the console's operational state, not the archive.

## 9. Tear down

```powershell
npx cdk destroy AcgwPilotFoundationStack
```

The user pool, all four DynamoDB tables (including the cost-rollup history), the console's S3
bucket and the audit log group are destroyed with the stack — deliberately, so a demo leaves
nothing behind. If you want the audit trail to outlive the stack
(a reasonable choice for a real deployment), change the audit log group's removal policy to
`RETAIN` in `pilot/foundation_stack.py`. Gateway and vended log groups may also survive; delete
them separately. Delete the stack when you are done; the gateway, Lambdas, tables, Cognito and
guardrail are individually cheap but none of them sit in a free tier, and Bedrock token usage
dominates the bill either way.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Synth fails: "Could not determine the target AWS account/region" | No credentials and no env override. Run `aws sts get-caller-identity`, or set `ACGW_ACCOUNT` / `ACGW_REGION`. |
| `ENOTEMPTY`, or an `atexit`/`OSError` on synth shutdown (Windows) | jsii temp-directory flake, not your code. `Get-ChildItem $env:TEMP -Directory -Filter "jsii-*" \| Remove-Item -Recurse -Force`, then retry. |
| "Another CLI is currently synthing to `cdk.out`" | A previous CDK process is still running. Wait for it, or synth to a different `-o` directory. |
| Deploy fails on bootstrap version | The account+region is not bootstrapped: `npx cdk bootstrap aws://<account>/<region>`. |
| `403` on **every** inference call, including `alice` | Usually model access. Re-check step 2 — an unauthorized model surfaces as an upstream denial, not a governance denial. |
| Inference returns `400` about `anthropic_version` | Anthropic models on this path require `anthropic_version: "bedrock-2023-05-31"` in the body. `pilot/inference_client.py` adds it. |
| Runtime path fails with `Credential should be scoped to correct service` | The runtime target must be an HTTP **passthrough** with an explicit signing service, not an inference target. See [`FINDINGS.md`](FINDINGS.md). |
| Inference fails with a guardrail-related `AccessDenied` | Your account or organization may *require* a guardrail on inference via the `bedrock:GuardrailIdentifier` condition key. The gateway role then needs `bedrock:ApplyGuardrail` on `guardrail/*` **and** `guardrail-profile/*` for cross-region guardrail profiles; the stack already grants both. Which surface this affects depends on how that policy is scoped — do not assume it matches what this repo observed. |
| `bedrock:InvokeModel` denied naming a region you did not target | Expected with cross-region inference profiles (`us.*`): they fan out to sibling regions, so the permission cannot be pinned to one region. The stack grants `arn:aws:bedrock:*::foundation-model/*` for this reason. |
| An admin change does not take effect | Wait out the cache TTL (`CONFIG_CACHE_TTL_SECONDS`, 10s). |
| Audit query returns fewer records than requests you made | Logs Insights indexing lag. Wait 1–2 minutes, or use `aws logs get-log-events` for an immediate read. |
| A request appears in the audit log as `allowed_no_prompt_text` | A recognised body shape yielded no extractable prompt (e.g. image-only), so there was nothing for a prompt guardrail to evaluate and the request was allowed. This is a deliberate, loudly-logged allow — distinct from an unrecognised shape, which fails closed. If the shape *does* carry prompt text the extractor missed, add its field to `_extract_text_units` in `pilot/lambda/guardrail/index.py`. |
| A denied request shows `decision: allowed` at REQUEST stage | Expected for **Cedar** group denials only: the interceptor runs before Cedar, so it allowed the request and Cedar denied it afterwards. Look for the unattributed `403` at RESPONSE stage. |
| Editing a seed value in `config.py` changes nothing | Config seeding is create-only, so redeploys never overwrite runtime edits. Change it in the console, or delete the table item. |
| Stack stuck in `UPDATE_ROLLBACK_FAILED` | `aws cloudformation continue-update-rollback --stack-name AcgwPilotFoundationStack --resources-to-skip <LogicalId>`. You may only skip resources that failed *during the rollback*. |
| Streaming arrives all at once | Expected. Output-token accounting requires a RESPONSE interceptor, which buffers. Set `ENABLE_OUTPUT_TOKEN_ACCOUNTING = False` in `pilot/config.py` to trade true-cost accounting for progressive streaming. |

## Security notes before you deploy

- **Demo-grade identity.** Four demo users whose passwords are generated at deploy time (or
  set via env var), surfaced as stack outputs, and the console uses the password flow rather
  than the hosted UI with PKCE. Fine for a demo, not for anything else.
- **The interceptor fails closed.** If `ApplyGuardrail` or a DynamoDB read errors, the request is
  denied (`403 governance_unavailable`) rather than allowed, and the failure logged. The one
  deliberate exception is a request shape yielding no prompt text, which is allowed and logged
  loudly — see the `allowed_no_prompt_text` row in the troubleshooting table. Break glass via the
  `(DEFAULT, BREAKGLASS)` config row if a governance bug is blocking legitimate traffic.
- **A synth-time guard blocks publicly invokable Lambdas.** `pilot/guards.py` fails the build on
  any wildcard Lambda principal or a Function URL with `authType=NONE`. It exists because a
  Function URL briefly made the admin console world-accessible. If you add a Lambda, the public
  surface must be API Gateway or CloudFront, never the function itself.
