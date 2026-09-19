"""Phase 1 foundation stack for the AgentCore Gateway inference-governance pilot.

Resources (all prefixed `acgw-pilot`, isolated in this stack):
  - Gateway execution IAM role
  - Self-contained Cognito IdP (pool, app client, groups)
  - AgentCore Gateway with a CUSTOM_JWT authorizer (Cognito)
  - Bedrock inference targets: connector (`bedrock`) + provider (`bedrockprov`)
  - Native per-user TPM rate limit (defense-in-depth only) + Cedar policy engine
  - Bedrock guardrail + REQUEST interceptor Lambda that enforces it

Uses the stable `aws_cdk.aws_bedrockagentcore` module. Gateway + target are the
L1 Cfn* constructs (no L2 inference-target helper exists yet). Nested property
shapes were verified by introspecting the installed 2.268.0 module.
"""
import json
import os

from aws_cdk import Stack, Tags, CfnOutput, Duration, RemovalPolicy, Aspects
from aws_cdk import aws_iam as iam
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_bedrock as bedrock
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_logs as logs
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import custom_resources as cr
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_integrations as apigw_int
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as events_targets
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3_deployment
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as cloudfront_origins
from aws_cdk import Fn
from constructs import Construct

from . import config
from .cognito import CognitoIdentity
from .guards import NoPublicLambdaAspect

_GUARDRAIL_LAMBDA_DIR = os.path.join(os.path.dirname(__file__), "lambda", "guardrail")
_ADMIN_LAMBDA_DIR = os.path.join(os.path.dirname(__file__), "lambda", "admin")
_USAGE_LAMBDA_DIR = os.path.join(os.path.dirname(__file__), "lambda", "usage")
_ROLLUP_LAMBDA_DIR = os.path.join(os.path.dirname(__file__), "lambda", "rollup")


def _load_admin_ui_html() -> str:
    """Return the admin console SPA HTML (the `_UI_HTML` constant in the admin handler).

    The single-file UI lives in the Lambda handler module so there is ONE copy of it,
    but that module cannot simply be imported here: at import it creates boto3 clients
    and reads required env vars (`CONFIG_TABLE` etc.), which are absent at synth time.
    So the string literal is extracted statically via the AST — no execution, no
    import-time side effects.
    """
    import ast

    src_path = os.path.join(_ADMIN_LAMBDA_DIR, "index.py")
    with open(src_path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Name) and target.id == "_UI_HTML"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)):
                    return node.value.value
    raise RuntimeError(
        f"_UI_HTML string constant not found in {src_path} — the admin console SPA "
        "source must define it at module scope for the CloudFront/S3 deployment."
    )
_PRICING_LAMBDA_DIR = os.path.join(os.path.dirname(__file__), "lambda", "pricing")


class FoundationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Fail the synth if any Lambda in this stack is ever made publicly invokable.
        # A Function URL with authType=NONE (which needs Principal "*") was briefly
        # deployed here and flagged by account security tooling; this makes that class of
        # regression impossible to ship rather than merely removed.
        Aspects.of(self).add(NoPublicLambdaAspect())

        Tags.of(self).add("project", "agentcore-inference-governance-pilot")
        Tags.of(self).add("prefix", config.PREFIX)

        # Self-contained Cognito IdP. ONE identity axis: group membership.
        # Cedar gates access on cognito:groups; the config table maps GROUP#/USER#
        # scopes to models, rate limits, budgets and guardrails.
        #
        # Construct id `Cognito3` (was Cognito2) forces a REPLACEMENT pool. Deleting the
        # `custom:tier` attribute in place is impossible — Cognito answers
        # "Existing schema attributes cannot be modified or deleted" — and renaming the
        # pool does not replace it either. Replacement is the only route. Clients are
        # unaffected: the notebook calls ic.discover(), which reads the stack-level
        # UserPoolId / UserPoolClientId outputs rather than hardcoding ids.
        self._cognito = CognitoIdentity(self, "Cognito3")

        # Policy engine must exist before the gateway (the gateway references it).
        self._policy_engine = self._build_policy_engine()

        self._gateway_role = self._build_gateway_role()

        # Guardrail enforcement via a REQUEST interceptor Lambda (the working path
        # after native guardrail-in-policy couldn't extract the prompt string from
        # the Messages array body — see findings.md). Built BEFORE the gateway
        # because the gateway's interceptor_configurations references the Lambda ARN.
        self._guardrail = self._build_bedrock_guardrail()
        # Cost ledger: the ONLY way to cap spend uniformly across both Bedrock
        # surfaces. Native token rate limits meter input tokens only and do not
        # apply to the runtime passthrough path at all.
        self._cost_ledger = self._build_cost_ledger()
        # Governance POLICY DATA as runtime state, not deploy-time config. The
        # interceptor reads this table on every request (cached briefly), so an
        # admin can change model access, budgets and guardrail selection without
        # a deployment. This is the prerequisite for an admin console.
        self._config_table = self._build_governance_config_table()
        # Real Bedrock rates, refreshed daily from the Price List API. Built before the
        # interceptors because both of them price requests from it.
        self._pricing_table = self._build_pricing()
        # Per-user daily/monthly cost aggregates, written OUT OF BAND by a scheduled
        # rollup Lambda that reads the ledger — deliberately NOT the interceptors, so the
        # hot path stays lean. This is what lets the console look back beyond the 24h
        # decision-record TTL and show daily/monthly spend per user.
        self._cost_rollup_table = self._build_cost_rollup(self._cost_ledger)
        # ONE audit destination for BOTH interceptors. Created before them because each
        # function is pointed at it via the Lambda `logGroup` property.
        self._audit_log_group = self._build_audit_log_group()
        self._guardrail_fn = self._build_guardrail_interceptor_fn(
            self._guardrail, self._cost_ledger, self._config_table
        )
        # RESPONSE interceptor for output-token accounting (separate Lambda).
        self._usage_fn = (
            self._build_usage_interceptor_fn(self._cost_ledger)
            if config.ENABLE_OUTPUT_TOKEN_ACCOUNTING
            else None
        )

        self._gateway = self._build_gateway(
            self._gateway_role, self._policy_engine, self._guardrail_fn, self._usage_fn
        )
        # Allow the gateway service to invoke the interceptor Lambda.
        self._guardrail_fn.add_permission(
            "AllowGatewayInvoke",
            principal=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            action="lambda:InvokeFunction",
            source_arn=self._gateway.attr_gateway_arn,
        )
        if self._usage_fn is not None:
            # Same two-grant requirement as the enforcement interceptor, and the resource
            # policy is scoped to THIS gateway (source_arn) rather than left open to any
            # AgentCore gateway.
            self._usage_fn.add_permission(
                "AllowGatewayInvokeUsage",
                principal=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
                action="lambda:InvokeFunction",
                source_arn=self._gateway.attr_gateway_arn,
            )
            self._gateway_role.add_to_policy(
                iam.PolicyStatement(
                    sid="InvokeUsageInterceptorLambda",
                    effect=iam.Effect.ALLOW,
                    actions=["lambda:InvokeFunction"],
                    resources=[self._usage_fn.function_arn],
                )
            )
        self._bedrock_target = self._build_runtime_inference_target(self._gateway)
        # Second target as an explicit PROVIDER (guardrail experiment). Built
        # alongside the connector so the proven connector path is undisturbed.
        self._provider_target = self._build_provider_inference_target(self._gateway)
        # THIRD target: the OTHER serverless surface, bedrock-runtime.
        # NOTE: target TYPE is immutable ("Target configuration cannot be updated
        # from provider to passthrough"), so switching this target from an inference
        # provider to a passthrough required deleting it first, then recreating it.
        self._runtime_target = self._build_runtime_provider_target(self._gateway)

        # Observability: deliver gateway logs + OTEL spans to CloudWatch so usage
        # can be attributed per user (the gateway calls Bedrock under ONE shared
        # role, so Bedrock's own logs can never tell users apart).
        self._observability = self._build_observability(self._gateway)

        # Admin console: JSON API on a Lambda behind an HTTP API, SPA on a private S3
        # bucket, both fronted by one CloudFront distribution (path-routed).
        (self._admin_fn, self._admin_api,
         self._admin_distribution) = self._build_admin_console(self._gateway)

        # Governance features under test.
        #
        # NO NATIVE RATE LIMITS. Both are gone, and for the same reason.
        #
        # The tier/model `rate:0` limit went first: it contradicted the config table (an
        # admin could allow a model in the console and still see it blocked on mantle by
        # a stale rate-limit entry). The per-user TPM limit on `jwt.sub` followed, once
        # rate limiting moved into the interceptor as the RATELIMIT config kind.
        #
        # Native limits attach only on RECOGNISED INFERENCE PATHS, so they never applied
        # to the bedrock-runtime passthrough target at all. That makes them a control
        # that covers half the traffic while looking fully configured — and calling the
        # remainder "defense-in-depth" flattered it, because the depth existed on exactly
        # one surface. With the Bedrock surfaces converging on the runtime endpoint over
        # time, a mantle-only control is a dead end rather than a safety net.
        #
        # The interceptor is now the SINGLE basis of enforcement, and it is FAIL CLOSED.
        # See _build_guardrail_interceptor_fn and docs/FINDINGS.md for the measured
        # gateway failure-mode matrix that makes that claim checkable.
        # Cedar owns exactly ONE question: may this caller use the gateway at all?
        # Renamed from _build_model_access_policy, which it never was — Cedar cannot see
        # the requested model. Model entitlement is an interceptor control.
        self._group_access_policy = self._build_group_access_policy(
            self._policy_engine, self._gateway
        )
        # GUARDRAIL-IN-POLICY (native) — DISABLED. Proven finding (see findings.md):
        # a provider target DOES surface the request body to context.input, but the
        # guardrail data-path argument requires a SCALAR STRING, and the Anthropic
        # Messages body has no flat string prompt field (the text is nested inside
        # `messages[].content[]`, typed Set<record>, unreachable by a scalar path).
        # So native guardrail-in-policy can't extract the prompt from a chat/messages
        # array body. We keep the provider target (working, documented) and enforce
        # guardrails via a request interceptor Lambda instead (see _build_* below).
        # self._guardrail_policy = self._build_guardrail_policy(
        #     self._policy_engine, self._gateway
        # )
        # self._guardrail_policy.add_dependency(self._provider_target)

        self._outputs()

    # ------------------------------------------------------------------ #
    def _build_gateway_role(self) -> iam.Role:
        """Execution role the gateway assumes to sign outbound Bedrock calls.

        With JWT inbound auth, outbound uses GATEWAY_IAM_ROLE — every inference
        call to Bedrock is signed by this role (that is why per-user attribution
        must come from the gateway layer, not Bedrock's logs).
        """
        role = iam.Role(
            self,
            "GatewayExecutionRole",
            role_name=f"{config.PREFIX}-gateway-exec-role",
            assumed_by=iam.ServicePrincipal("bedrock-agentcore.amazonaws.com"),
            description="Execution role for the AgentCore inference-governance pilot gateway.",
            managed_policies=[
                # The bedrock-mantle connector is a distinct service. On target
                # creation the gateway calls bedrock-mantle:ListModels (model
                # discovery) and later CreateInference. This AWS-managed policy
                # grants exactly those (Get*/List*/CreateInference/CallWithBearerToken).
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonBedrockMantleInferenceAccess"
                ),
            ],
        )
        # Also allow classic Bedrock InvokeModel on foundation/inference-profile
        # models (mirrors the AWS reference execution role, which pairs both).
        role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeBedrockModels",
                effect=iam.Effect.ALLOW,
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                resources=[
                    # NOT pinned to one region on purpose. bedrock-runtime's
                    # cross-region inference profiles (the `us.*` ids) fan requests
                    # out to sibling regions, so invoking
                    # `us.anthropic.claude-sonnet-5` from us-east-1 requires
                    # bedrock:InvokeModel on the underlying foundation model in
                    # OTHER regions too. Pinning to us-east-1 produced:
                    #   403 not authorized to perform: bedrock:InvokeModel on
                    #   resource: arn:aws:bedrock:us-east-2::foundation-model/...
                    "arn:aws:bedrock:*::foundation-model/*",
                    f"arn:aws:bedrock:{config.AWS_REGION}:{config.AWS_ACCOUNT}:inference-profile/*",
                    f"arn:aws:bedrock:*:{config.AWS_ACCOUNT}:inference-profile/*",
                ],
            )
        )
        # When a policy engine is attached, the gateway role must read the engine
        # and evaluate authorization. The pre-flight check exercises both
        # GetPolicyEngine and AuthorizeAction against BOTH the policy-engine and
        # gateway resources, so grant both actions on both ARN types.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="PolicyEngineEvaluation",
                effect=iam.Effect.ALLOW,
                # The gateway's policy pre-flight + runtime evaluation exercises
                # several bedrock-agentcore authorize/policy actions (GetPolicyEngine,
                # AuthorizeAction, PartiallyAuthorizeActions, ...). Grant the
                # policy-evaluation action surface, scoped to this account's
                # policy-engine and gateway resources.
                actions=[
                    "bedrock-agentcore:GetPolicyEngine",
                    "bedrock-agentcore:AuthorizeAction",
                    "bedrock-agentcore:PartiallyAuthorizeActions",
                    "bedrock-agentcore:BatchAuthorizeActions",
                    "bedrock-agentcore:GetPolicy",
                    "bedrock-agentcore:ListPolicies",
                ],
                resources=[
                    f"arn:aws:bedrock-agentcore:{config.AWS_REGION}:{config.AWS_ACCOUNT}:policy-engine/*",
                    f"arn:aws:bedrock-agentcore:{config.AWS_REGION}:{config.AWS_ACCOUNT}:gateway/*",
                ],
            )
        )
        # Guardrails-in-policy: the Policy data plane uses FAS credentials from
        # this role to call the Bedrock Guardrails API. Requires
        # bedrock:InvokeGuardrailChecks.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeGuardrailChecks",
                effect=iam.Effect.ALLOW,
                actions=["bedrock:InvokeGuardrailChecks"],
                resources=["*"],
            )
        )
        # FINDING — ENVIRONMENT-DEPENDENT, granted defensively.
        #
        # An account or organization can REQUIRE a guardrail on inference using the
        # `bedrock:GuardrailIdentifier` condition key (identity policy or SCP), which
        # denies InvokeModel / Converse / InvokeModelWithResponseStream calls that do
        # not carry the mandated guardrail. Where that is in force, the *caller* must
        # also be allowed to apply it. In the account this was developed in, routing
        # through the runtime target failed with:
        #   403 not authorized to perform: bedrock:ApplyGuardrail on resource:
        #       arn:aws:bedrock:...:guardrail/<id>
        # for a guardrail this stack does not own, while mantle showed no such
        # requirement — because a policy written against the runtime action names does
        # not necessarily cover mantle's separate API surface.
        #
        # Do NOT generalise that split: which surface is affected depends entirely on
        # how the controlling policy is scoped, and another account may enforce on
        # both, neither, or the opposite one. This grant is therefore unconditional —
        # a no-op where no such policy exists, and it prevents an opaque AccessDenied
        # where one does. Scoped to guardrails in THIS account rather than a specific
        # ARN, because which guardrail is mandated is not this stack's decision.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="ApplyGuardrailForRuntimeInvocations",
                effect=iam.Effect.ALLOW,
                actions=["bedrock:ApplyGuardrail"],
                resources=[
                    # Both resource types are needed, and they surface one at a time:
                    # granting only `guardrail/*` moved the denial on to
                    # `guardrail-profile/us.guardrail.v1:0` — a CROSS-REGION guardrail
                    # profile, the same pattern as inference profiles. Not pinned to a
                    # single region for that reason.
                    f"arn:aws:bedrock:*:{config.AWS_ACCOUNT}:guardrail/*",
                    f"arn:aws:bedrock:*:{config.AWS_ACCOUNT}:guardrail-profile/*",
                ],
            )
        )
        # The gateway invokes the REQUEST interceptor Lambda under THIS execution
        # role (identity-based), in addition to the Lambda's own resource policy.
        # The "Access denied while invoking Lambda" error names the gateway exec
        # role explicitly — grant lambda:InvokeFunction on the interceptor.
        role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeInterceptorLambda",
                effect=iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=[
                    f"arn:aws:lambda:{config.AWS_REGION}:{config.AWS_ACCOUNT}:function:{config.PREFIX}-guardrail-interceptor",
                ],
            )
        )
        return role

    # ------------------------------------------------------------------ #
    def _build_pricing(self) -> dynamodb.Table:
        """Model pricing as refreshed DATA, not code, plus the Lambda that refreshes it.

        WHY: cost enforcement on hardcoded rates is wrong the moment AWS changes one.
        Measured against the live Price List API, the illustrative constants this repo
        shipped with priced claude-opus-5 at 3x its real rate. A budget built on that is
        not a budget.

        The refresh Lambda is invoked ONCE on create as well as daily, because an empty
        pricing table on a fresh deploy would silently fall back to the constants — the
        exact failure mode this table exists to remove.
        """
        table = dynamodb.Table(
            self,
            "ModelPricing",
            table_name=config.PRICING_TABLE_NAME,
            partition_key=dynamodb.Attribute(
                name="model_key", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        fn = _lambda.Function(
            self,
            "PricingSyncFn",
            function_name=f"{config.PREFIX}-pricing-sync",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(_PRICING_LAMBDA_DIR),
            # The Price List API returns ~1400 products across the two service codes
            # and is paginated 100 at a time, so this needs real time.
            timeout=Duration.minutes(5),
            memory_size=512,
            environment={
                "PRICING_TABLE": table.table_name,
                "RATE_SCOPE": config.PRICING_RATE_SCOPE,
            },
            description=("Daily Bedrock price refresh from the AWS Price List API "
                         "(both AmazonBedrock and AmazonBedrockFoundationModels)."),
        )
        table.grant_read_write_data(fn)
        # The Price List API is not resource-scopable.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadAwsPriceList",
                effect=iam.Effect.ALLOW,
                actions=["pricing:GetProducts", "pricing:DescribeServices",
                         "pricing:GetAttributeValues"],
                resources=["*"],
            )
        )

        events.Rule(
            self,
            "PricingSyncSchedule",
            rule_name=f"{config.PREFIX}-pricing-sync-daily",
            schedule=events.Schedule.cron(
                minute="0", hour=str(config.PRICING_REFRESH_HOUR_UTC)
            ),
            targets=[events_targets.LambdaFunction(fn)],
            description="Refresh Bedrock model pricing from the AWS Price List API.",
        )

        # Prime the table on first deploy so nothing ever runs on the fallback constants
        # just because the schedule has not fired yet.
        prime = cr.AwsCustomResource(
            self,
            "PricingSyncOnCreate",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={"FunctionName": fn.function_name,
                            "InvocationType": "Event"},
                physical_resource_id=cr.PhysicalResourceId.of("pricing-sync-prime"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                    actions=["lambda:InvokeFunction"],
                                    resources=[fn.function_arn])
            ]),
            install_latest_aws_sdk=False,
        )
        prime.node.add_dependency(fn)
        return table

    # ------------------------------------------------------------------ #
    def _build_cost_rollup(self, ledger: dynamodb.Table) -> dynamodb.Table:
        """Per-user daily/monthly cost aggregates + the Lambda that computes them.

        DELIBERATELY OUT OF BAND. The two interceptors are on the request/response hot
        path and must stay lean and fail closed — the request interceptor's own timeout
        makes the GATEWAY fail open, so non-essential work there is a liability. Rolling
        up cost history is non-essential to enforcement, so it runs here on a schedule,
        reading what the interceptors already wrote and never touching their code path.

        The aggregates outlive the `DECISION#` records they are derived from (24h TTL),
        which is what lets the console look back weeks and show daily/monthly spend. The
        job also harvests the `sub -> username` pairing (present on decision rows) into a
        small map, so the console can label the sub-keyed live spend counters with names.
        """
        table = dynamodb.Table(
            self,
            "CostRollup",
            table_name=config.COST_ROLLUP_TABLE_NAME,
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,
        )

        fn = _lambda.Function(
            self,
            "CostRollupFn",
            function_name=f"{config.PREFIX}-cost-rollup",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(_ROLLUP_LAMBDA_DIR),
            # A single ledger scan; generous headroom for a large table.
            timeout=Duration.minutes(2),
            memory_size=256,
            environment={
                "COST_LEDGER_TABLE": ledger.table_name,
                "COST_ROLLUP_TABLE": table.table_name,
                "ROLLUP_TTL_SECONDS": str(config.COST_ROLLUP_TTL_SECONDS),
            },
            description=("Out-of-band cost rollup: per-user daily/monthly aggregates "
                         "from the ledger. NOT on any request path."),
        )
        ledger.grant_read_data(fn)
        table.grant_read_write_data(fn)

        events.Rule(
            self,
            "CostRollupSchedule",
            rule_name=f"{config.PREFIX}-cost-rollup",
            schedule=events.Schedule.rate(
                Duration.minutes(config.COST_ROLLUP_INTERVAL_MINUTES)
            ),
            targets=[events_targets.LambdaFunction(fn)],
            description="Recompute per-user daily/monthly cost aggregates from the ledger.",
        )

        # Prime once on create so the console has aggregates immediately rather than
        # waiting for the first scheduled run.
        prime = cr.AwsCustomResource(
            self,
            "CostRollupOnCreate",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={"FunctionName": fn.function_name,
                            "InvocationType": "Event"},
                physical_resource_id=cr.PhysicalResourceId.of("cost-rollup-prime"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                    actions=["lambda:InvokeFunction"],
                                    resources=[fn.function_arn])
            ]),
            install_latest_aws_sdk=False,
        )
        prime.node.add_dependency(fn)
        return table

    # ------------------------------------------------------------------ #
    def _build_audit_log_group(self) -> logs.LogGroup:
        """ONE searchable audit log for every governance decision, both stages.

        WHY THIS EXISTS
        ---------------
        A security reviewer needs one place to answer "who asked what, of which model,
        and what did we do about it" — and none of the obvious candidates can:

          * **Bedrock invocation logging** is an account-level setting this stack does
            not own, mantle does not offer it, and it only records calls that REACH
            Bedrock. A guardrail denial never does, so the most security-relevant
            events would be missing entirely.
          * **Gateway OTEL spans** carry no identity and no token counts, and
            interceptor short-circuits are not spanned at all.
          * **The DynamoDB decision records** are the console's data source and carry a
            24-hour TTL (`config.DECISION_RECORD_TTL_SECONDS`) — deliberately shorter
            than this log, because they are operational state, not an archive. That TTL
            is also the console's history horizon, so it must not be shorter than the
            longest range the UI offers.

        HOW
        ---
        Rather than have the Lambdas call PutLogEvents into a separate group (extra IAM,
        a log-stream lifecycle to manage, and a 5 TPS-per-stream throttling ceiling),
        BOTH interceptors are pointed at this group as their own function log group. A
        structured `print` therefore lands in the single destination, and the request and
        response records for one call join on `request_id`.

        Retention is real (90 days by default) precisely because the decision records
        are not, and field indexes keep identity/decision queries fast as it grows.
        """
        # MASK SENSITIVE DATA AT INGEST. This is what makes opting into prompt and
        # response logging defensible rather than reckless: a reader sees
        # `***MASKED***` unless they separately hold `logs:Unmask`. It is enabled even
        # while content logging is off, because content is not the only leak path — a
        # guardrail assessment, an error string or a tool argument can carry an
        # identifier too.
        data_protection = None
        if config.AUDIT_DATA_PROTECTION_ENABLED:
            data_protection = logs.DataProtectionPolicy(
                name=f"{config.PREFIX}-audit-data-protection",
                description=("Mask PII and secrets in governance audit records at "
                             "ingest; unmasking requires logs:Unmask."),
                identifiers=[
                    getattr(logs.DataIdentifier, name)
                    for name in config.AUDIT_DATA_PROTECTION_IDENTIFIERS
                ],
            )

        return logs.LogGroup(
            self,
            "GovernanceAuditLogGroup",
            log_group_name=config.AUDIT_LOG_GROUP_NAME,
            data_protection_policy=data_protection,
            retention=getattr(logs.RetentionDays, config.AUDIT_LOG_RETENTION),
            # Field indexes make the common security queries cheap as volume grows.
            field_index_policies=[
                logs.FieldIndexPolicy(
                    fields=["request_id", "username", "decision", "model"]
                )
            ],
            removal_policy=RemovalPolicy.DESTROY,
        )

    # ------------------------------------------------------------------ #
    def _build_usage_interceptor_fn(self, ledger: dynamodb.Table) -> _lambda.Function:
        """RESPONSE interceptor: output-token accounting.

        Separate from the enforcement interceptor on purpose — different job, different
        interception point, and keeping them apart means the enforcement path is
        unaffected by anything that happens here.
        """
        fn = _lambda.Function(
            self,
            "UsageInterceptorFn",
            function_name=f"{config.PREFIX}-usage-interceptor",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(_USAGE_LAMBDA_DIR),
            timeout=Duration.seconds(15),
            memory_size=256,
            environment={
                "COST_LEDGER_TABLE": ledger.table_name,
                "MODEL_PRICES_JSON": json.dumps(config.MODEL_INPUT_PRICES_PER_1K),
                "MODEL_OUTPUT_PRICES_JSON": json.dumps(config.MODEL_OUTPUT_PRICES_PER_1K),
                "PROBE_MODE": str(config.USAGE_PROBE_MODE).lower(),
                "AUDIT_LOG_RESPONSE_TEXT": str(config.AUDIT_LOG_RESPONSE_TEXT).lower(),
                "AUDIT_LOG_RESPONSE_MAX_CHARS": str(config.AUDIT_LOG_RESPONSE_MAX_CHARS),
                "PRICING_TABLE": self._pricing_table.table_name,
                "PRICING_CACHE_TTL_SECONDS": str(config.PRICING_CACHE_TTL_SECONDS),
                "PRICING_STALE_AFTER_SECONDS": str(config.PRICING_STALE_AFTER_SECONDS),
            },
            # Both interceptors log into the SHARED audit group, so the request and
            # response halves of one call are searchable together.
            log_group=self._audit_log_group,
            description="Gateway RESPONSE interceptor: reconcile true spend incl. output tokens.",
        )
        ledger.grant_read_write_data(fn)
        self._pricing_table.grant_read_data(fn)
        # NOTE: the invoke permission is granted in the constructor AFTER the gateway
        # exists, so it can be scoped with source_arn to THIS gateway. Granting it here
        # would mean an unconstrained service principal (any AgentCore gateway, in any
        # account, could invoke this function) — needlessly broad.
        return fn

    # ------------------------------------------------------------------ #
    def _build_gateway(
        self,
        role: iam.Role,
        policy_engine: agentcore.CfnPolicyEngine,
        guardrail_fn: _lambda.Function,
        usage_fn: _lambda.Function = None,
    ) -> agentcore.CfnGateway:
        """AgentCore Gateway with a Cognito CUSTOM_JWT inbound authorizer.

        Path A: the authorizer validates issuer (via Cognito discovery URL) and
        audience (the app client id — Cognito access tokens set `aud`/`client_id`
        to the app client id). We do NOT set allowed_scopes: InitiateAuth access
        tokens carry no custom scope. Authorization (which group may use which
        model) is enforced by Cedar keyed on `cognito:groups`.
        """
        discovery_url = config.cognito_discovery_url(
            config.AWS_REGION, self._cognito.user_pool.user_pool_id
        )
        # Cognito ACCESS tokens have no `aud` claim — the client identity is in
        # `client_id`, validated by allowed_clients. Setting allowed_audience
        # would require an `aud` match that never succeeds (403 insufficient_scope
        # / invalid_token). So use allowed_clients ONLY for Cognito.
        jwt_cfg = agentcore.CfnGateway.CustomJWTAuthorizerConfigurationProperty(
            discovery_url=discovery_url,
            allowed_clients=[self._cognito.user_pool_client.user_pool_client_id],
        )
        authorizer_cfg = agentcore.CfnGateway.AuthorizerConfigurationProperty(
            custom_jwt_authorizer=jwt_cfg,
        )

        # Attach the Cedar policy engine so the gateway evaluates policies on
        # every request. Mode ENFORCING = deny-by-default deterministic control.
        policy_engine_cfg = agentcore.CfnGateway.GatewayPolicyEngineConfigurationProperty(
            arn=policy_engine.attr_policy_engine_arn,
            mode="ENFORCE",  # valid: LOG_ONLY | ENFORCE
        )

        # REQUEST interceptor: enforcement (model access, cost budget, guardrail).
        # Inference targets share the HTTP interceptor payload (base64 body).
        # pass_request_headers=True gives it the inbound JWT, which is how it knows
        # WHO is calling — the basis of every per-principal decision.
        interceptor_cfgs = [
            agentcore.CfnGateway.GatewayInterceptorConfigurationProperty(
                interception_points=["REQUEST"],
                interceptor=agentcore.CfnGateway.InterceptorConfigurationProperty(
                    lambda_=agentcore.CfnGateway.LambdaInterceptorConfigurationProperty(
                        arn=guardrail_fn.function_arn,
                    ),
                ),
                input_configuration=agentcore.CfnGateway.InterceptorInputConfigurationProperty(
                    pass_request_headers=True,
                ),
            ),
        ]

        # RESPONSE interceptor: output-token accounting, as a SEPARATE Lambda so the
        # enforcement path stays untouched. Only the response carries
        # `usage.output_tokens`, and output tokens dominate real spend — a prompt-only
        # ledger understates cost.
        #
        # TRADE-OFF, accepted deliberately: response interception on HTTP/inference
        # targets is BUFFERED, so attaching this costs token-by-token streaming.
        # Set config.ENABLE_OUTPUT_TOKEN_ACCOUNTING = False to get streaming back.
        if config.ENABLE_OUTPUT_TOKEN_ACCOUNTING and usage_fn is not None:
            interceptor_cfgs.append(
                agentcore.CfnGateway.GatewayInterceptorConfigurationProperty(
                    interception_points=["RESPONSE"],
                    interceptor=agentcore.CfnGateway.InterceptorConfigurationProperty(
                        lambda_=agentcore.CfnGateway.LambdaInterceptorConfigurationProperty(
                            arn=usage_fn.function_arn,
                        ),
                    ),
                    # Request headers requested here too: the documented HTTP response
                    # payload shows `gatewayRequest: null`, which would leave no JWT and
                    # therefore no way to attribute tokens to a user. Whether this flag
                    # changes that is exactly what the probe measures.
                    input_configuration=agentcore.CfnGateway.InterceptorInputConfigurationProperty(
                        pass_request_headers=True,
                    ),
                )
            )

        gateway = agentcore.CfnGateway(
            self,
            "Gateway",
            name=f"{config.PREFIX}-gateway",
            role_arn=role.role_arn,
            authorizer_type="CUSTOM_JWT",
            authorizer_configuration=authorizer_cfg,
            policy_engine_configuration=policy_engine_cfg,
            interceptor_configurations=interceptor_cfgs,
            # ProtocolType is optional at the gateway level. Inference capability
            # comes from the attached inference TARGET, not a gateway protocol
            # value (the CFN INFERENCE enum lives on passthrough targets, and the
            # gateway's only protocol config today is MCP). Omit and let the
            # service default; revisit only if deploy requires an explicit value.
            description="Inference-governance pilot gateway (Cognito JWT inbound, Bedrock outbound).",
        )
        return gateway

    # ------------------------------------------------------------------ #
    def _build_runtime_inference_target(
        self, gateway: agentcore.CfnGateway
    ) -> agentcore.CfnGatewayTarget:
        """Single Bedrock inference connector target.

        The only valid connector IDs are `bedrock-mantle`, `openai`, `anthropic`
        (verified against the control-API reference — there is NO `bedrock-runtime`
        connector). `bedrock-mantle` IS the Bedrock connector. Bedrock connectors
        use GATEWAY_IAM_ROLE outbound with no iamCredentialProvider sub-object
        (the service is already known to the gateway).
        """
        target_cfg = agentcore.CfnGatewayTarget.TargetConfigurationProperty(
            inference=agentcore.CfnGatewayTarget.InferenceTargetConfigurationProperty(
                connector=agentcore.CfnGatewayTarget.InferenceConnectorTargetConfigurationProperty(
                    source=agentcore.CfnGatewayTarget.InferenceConnectorSourceProperty(
                        connector_id=config.MODELS.connector_id,
                    ),
                ),
            ),
        )
        cred_cfg = agentcore.CfnGatewayTarget.CredentialProviderConfigurationProperty(
            credential_provider_type="GATEWAY_IAM_ROLE",
        )

        target = agentcore.CfnGatewayTarget(
            self,
            "BedrockInferenceTarget",
            name="bedrock",
            gateway_identifier=gateway.attr_gateway_identifier,
            target_configuration=target_cfg,
            credential_provider_configurations=[cred_cfg],
            description="Bedrock inference connector target (bedrock-mantle connector).",
        )
        target.add_dependency(gateway)
        return target

    # ------------------------------------------------------------------ #
    def _build_provider_inference_target(
        self, gateway: agentcore.CfnGatewayTarget
    ) -> agentcore.CfnGatewayTarget:
        """SECOND inference target, built as an explicit PROVIDER (guardrail probe).

        The connector target declares no input schema, so `context.input.prompt`
        / `.body` are "not present" for the guardrail policy. A provider target
        declares operations/paths/models explicitly. This experiment tests
        whether that explicit declaration surfaces request content to the
        guardrail — the open question blocking the guardrail goal.

        Shape (introspected on 2.268.0):
          InferenceProviderTargetConfigurationProperty(endpoint, model_mapping, operations)
          InferenceOperationConfigurationProperty(path, provider_path, models=[ModelEntryProperty(model)])
          ModelMappingProperty(provider_prefix=ProviderPrefixProperty(separator, strip))

        Follows the documented Bedrock provider example: endpoint
        https://bedrock-mantle.us-east-1.api.aws, providerPrefix.strip on ".",
        operation /v1/messages -> providerPath /anthropic/v1/messages.
        """
        operation = agentcore.CfnGatewayTarget.InferenceOperationConfigurationProperty(
            path=config.MODELS.provider_op_path,
            provider_path=config.MODELS.provider_op_provider_path,
            models=[
                agentcore.CfnGatewayTarget.ModelEntryProperty(
                    model=config.MODELS.provider_model_glob,
                )
            ],
        )
        model_mapping = agentcore.CfnGatewayTarget.ModelMappingProperty(
            provider_prefix=agentcore.CfnGatewayTarget.ProviderPrefixProperty(
                separator=config.MODELS.provider_prefix_separator,
                strip=True,
            ),
        )
        provider_cfg = agentcore.CfnGatewayTarget.InferenceProviderTargetConfigurationProperty(
            endpoint=config.MODELS.provider_endpoint,
            model_mapping=model_mapping,
            operations=[operation],
        )
        target_cfg = agentcore.CfnGatewayTarget.TargetConfigurationProperty(
            inference=agentcore.CfnGatewayTarget.InferenceTargetConfigurationProperty(
                provider=provider_cfg,
            ),
        )
        cred_cfg = agentcore.CfnGatewayTarget.CredentialProviderConfigurationProperty(
            credential_provider_type="GATEWAY_IAM_ROLE",
        )
        target = agentcore.CfnGatewayTarget(
            self,
            "BedrockProviderTarget",
            name=config.MODELS.provider_target_name,
            gateway_identifier=gateway.attr_gateway_identifier,
            target_configuration=target_cfg,
            credential_provider_configurations=[cred_cfg],
            # Description kept current on purpose: this is the first thing anyone
            # reviewing the gateway reads. It began life as a probe for whether a provider
            # target exposes the request body to guardrail-in-policy (it does; the scalar
            # data-path limit is what blocked that), and it is now the DEFAULT serving path.
            description=("Bedrock inference PROVIDER target on bedrock-mantle - "
                         "the DEFAULT serving path."),
        )
        target.add_dependency(gateway)
        return target

    # ------------------------------------------------------------------ #
    def _build_runtime_provider_target(
        self, gateway: agentcore.CfnGateway
    ) -> agentcore.CfnGatewayTarget:
        """THIRD target: **bedrock-runtime**, the second serverless surface.

        This target is what makes the "unified governance plane" claim real: the
        same Cedar policies, rate limits, and guardrail interceptor must apply no
        matter which Bedrock surface serves the request.

        WHY THIS IS A PASSTHROUGH TARGET AND NOT AN INFERENCE TARGET
        -----------------------------------------------------------
        Fronting runtime with an *inference* target does not work today. Verified,
        in order:
          1. There is **no `bedrock-runtime` connector** — valid connector IDs are
             only `bedrock-mantle`, `openai`, `anthropic`.
          2. An inference **provider** target aimed at
             `https://bedrock-runtime.us-east-1.amazonaws.com` reaches runtime and
             routes correctly (model-based routing resolves, the Anthropic Messages
             body is accepted verbatim, and runtime even tolerates the extra
             top-level `model` field the gateway forwards). But every request fails:
                 403 "Credential should be scoped to correct service: 'bedrock'."
             The gateway derives the SigV4 service name from the endpoint hostname
             (`bedrock-runtime`), whereas runtime's signing service is **`bedrock`**.
             Signing the exact same request with service `bedrock` by hand returns a
             normal 200 completion, which isolates the defect to the service name.
          3. The override for that (`IamCredentialProvider`) is **rejected on
             inference targets**:
                 "IamCredentialProvider is not supported for this target type. Only
                  MCP Server, OpenAPI, and Passthrough targets can configure
                  IamCredentialProvider."
          4. Pointing at the control-plane host `bedrock.us-east-1.amazonaws.com`
             (which *would* derive the right signing service) returns
             `UnknownOperationException` — it does not serve the invoke API.

        A **passthrough** target with `protocolType=INFERENCE` is therefore the only
        route: it is one of the target types permitted to set an explicit signing
        service, and for well-known providers (including Amazon Bedrock) the service
        applies a default inference schema based on the endpoint domain, which is
        what lets policy-engine features attach.
        """
        passthrough_cfg = agentcore.CfnGatewayTarget.PassthroughTargetConfigurationProperty(
            endpoint=config.MODELS.runtime_endpoint,
            # INFERENCE (not CUSTOM) so the gateway treats this as an LLM endpoint
            # and applies the default Bedrock inference schema.
            protocol_type="INFERENCE",
        )
        target_cfg = agentcore.CfnGatewayTarget.TargetConfigurationProperty(
            http=agentcore.CfnGatewayTarget.HttpTargetConfigurationProperty(
                passthrough=passthrough_cfg,
            ),
        )
        target = agentcore.CfnGatewayTarget(
            self,
            "BedrockRuntimeTarget",
            name=config.MODELS.runtime_target_name,
            gateway_identifier=gateway.attr_gateway_identifier,
            target_configuration=target_cfg,
            credential_provider_configurations=[
                agentcore.CfnGatewayTarget.CredentialProviderConfigurationProperty(
                    credential_provider_type="GATEWAY_IAM_ROLE",
                    # The whole reason this is a passthrough target: set the SigV4
                    # signing service explicitly to `bedrock` (NOT the hostname-derived
                    # `bedrock-runtime`).
                    credential_provider=agentcore.CfnGatewayTarget.CredentialProviderProperty(
                        iam_credential_provider=agentcore.CfnGatewayTarget.IamCredentialProviderProperty(
                            service="bedrock",
                            region=config.AWS_REGION,
                        ),
                    ),
                )
            ],
            description="bedrock-runtime via HTTP passthrough (protocolType=INFERENCE, signing service=bedrock).",
        )
        target.add_dependency(gateway)
        return target

    # ------------------------------------------------------------------ #
    def _build_bedrock_guardrail(self) -> bedrock.CfnGuardrail:
        """A Bedrock Guardrail the interceptor calls via ApplyGuardrail.

        Focused on the pilot's headline control: PROMPT_ATTACK (prompt injection)
        detection on INPUT, plus a couple of content filters. The interceptor
        extracts the caller's prompt text and evaluates it against this guardrail;
        GUARDRAIL_INTERVENED -> the request is blocked (403) before Bedrock is called.
        """
        return bedrock.CfnGuardrail(
            self,
            "InferenceGuardrail",
            name=f"{config.PREFIX}-guardrail",
            description="Prompt-injection + content guardrail enforced at the gateway via interceptor.",
            blocked_input_messaging="This request was blocked by the gateway guardrail.",
            blocked_outputs_messaging="This response was blocked by the gateway guardrail.",
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                filters_config=[
                    # PROMPT_ATTACK only supports input filtering; output_strength
                    # must be NONE for this type.
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="PROMPT_ATTACK",
                        input_strength="HIGH",
                        output_strength="NONE",
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="HATE",
                        input_strength="HIGH",
                        output_strength="HIGH",
                    ),
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(
                        type="VIOLENCE",
                        input_strength="HIGH",
                        output_strength="HIGH",
                    ),
                ],
            ),
        )

    # ------------------------------------------------------------------ #
    def _build_cost_ledger(self) -> dynamodb.Table:
        """Per-user spend ledger, keyed by user + time window.

        WHY A LEDGER IS REQUIRED (not a nice-to-have):
          * Native token rate limits meter **input tokens only** — output tokens,
            which dominate real spend, are never counted. So they cap prompt
            volume, not cost.
          * They also only apply on known inference paths, so they do **nothing**
            for the bedrock-runtime passthrough target.
        Accumulating estimated cost here, in the interceptor's datastore, is what
        makes cost governance work identically on BOTH surfaces.

        The window key keeps this a fixed-window counter (simple, cheap, and easy
        to reason about); TTL lets DynamoDB expire old windows automatically.
        """
        return dynamodb.Table(
            self,
            "CostLedger",
            table_name=f"{config.PREFIX}-cost-ledger",
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY,
        )

    # ------------------------------------------------------------------ #
    def _build_governance_config_table(self) -> dynamodb.Table:
        """Governance policy data: which models, what budget, which guardrail.

        WHY: previously these lived in the interceptor's environment variables,
        which makes them **deploy-time** settings. An admin console cannot change
        a Lambda env var meaningfully, so policy data has to become runtime state.
        Infrastructure stays in CDK; policy data lives here.

        SHAPE (single table, scope + kind):
            pk = "DEFAULT" | "GROUP#<group>" | "USER#<username>"
            sk = "MODELS" | "BUDGET" | "RATELIMIT" | "GUARDRAIL"

        RESOLUTION PRECEDENCE (most specific wins, evaluated per kind):
            USER#<username>  ->  GROUP#<group>  ->  DEFAULT

        SHAPE (single table, scope + kind) — plus one operational row:
            pk = "DEFAULT", sk = "BREAKGLASS"

        Attributes by kind:
            MODELS     : allow[] / deny[] glob lists matched against the model id
            BUDGET     : budget_usd, window_seconds
            RATELIMIT  : tokens_per_window, requests_per_window, window_seconds, pooled
            GUARDRAIL  : guardrail_id, enabled
            BREAKGLASS : enabled, reason, set_by  (DEFAULT scope only)

        Seeding is **onCreate only, deliberately**. A redeploy must NOT clobber
        changes an administrator made at runtime. The consequence is that changing
        a seed value in code has no effect on an existing table — edit through the
        admin API instead, which is the intended path.
        """
        table = dynamodb.Table(
            self,
            "GovernanceConfig",
            table_name=f"{config.PREFIX}-governance-config",
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="sk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        def _s(v: str) -> dict:
            return {"S": v}

        def _globs(values: list) -> dict:
            return {"L": [{"S": v} for v in values]}

        def _put(pk: str, sk: str, **attrs) -> dict:
            item = {"pk": _s(pk), "sk": _s(sk)}
            item.update(attrs)
            return {"PutRequest": {"Item": item}}

        # Seed reproduces the behaviour previously hardcoded in env vars, so the
        # table is the source of truth from the first deploy onward.
        seed_items = [
            # ---- defaults: premium DENIED here, demo budget, guardrail on -----
            # The deny lives at the DEFAULT scope and a group row grants the exception.
            # That inversion is what replaced the tier axis: entitlement is now a
            # property of group membership, not of a claim baked into the token.
            _put("DEFAULT", "MODELS",
                 allow=_globs(["*"]), deny=_globs(["*claude-opus*"])),
            # Dual calendar budgets: independent daily + monthly caps, EITHER can deny.
            # (Replaces the single fixed-window budget. The interceptor still honours a
            # legacy `budget_usd`/`window_seconds` row for backward compatibility, but new
            # deployments seed the calendar form.)
            _put(
                "DEFAULT",
                "BUDGET",
                daily_budget_usd={"N": str(config.DEMO_COST_DAILY_BUDGET_USD)},
                monthly_budget_usd={"N": str(config.DEMO_COST_MONTHLY_BUDGET_USD)},
            ),
            # The VERSION is seeded alongside the id because the two are a pair: the same
            # id serves a mutable DRAFT and any number of published versions carrying
            # different content policies. The interceptor previously took the version
            # from an env var, which stopped being coherent once the admin console could
            # bind any guardrail in the account — the id came from policy while the
            # version came from this stack's own guardrail. See `_apply_guardrail`.
            _put(
                "DEFAULT",
                "GUARDRAIL",
                guardrail_id=_s(self._guardrail.attr_guardrail_id),
                guardrail_version=_s(self._guardrail.attr_version),
                enabled={"BOOL": True},
            ),
            # ---- default rate limit: per-user, not pooled ---------------------
            _put(
                "DEFAULT",
                "RATELIMIT",
                tokens_per_window={"N": str(config.DEMO_RATE_TOKENS_PER_WINDOW)},
                requests_per_window={"N": str(config.DEMO_RATE_REQUESTS_PER_WINDOW)},
                window_seconds={"N": str(config.DEMO_RATE_WINDOW_SECONDS)},
                pooled={"BOOL": False},
            ),
            # ---- GROUP entitlement (replaces the deleted TIER rows) -----------
            # The premium model is denied by DEFAULT and re-allowed for the research
            # group. Expressing it as "deny at the default, permit for a group" rather
            # than "deny for a tier" is what makes group membership the single axis:
            # add someone to ml-research and their entitlement changes, no claim to
            # re-issue and no token to refresh.
            #
            # One glob covers BOTH surfaces (mantle `anthropic.claude-opus-5` and
            # runtime `us.anthropic.claude-opus-5`).
            _put(
                f"GROUP#{config.COGNITO_GROUP_RESEARCH}",
                "MODELS",
                allow=_globs(["*"]),
                deny=_globs([]),
            ),
            # A POOLED allowance for the research group: 3x the per-user token budget,
            # but SHARED across the group rather than granted to each member. This is
            # the thing a native rate limit keyed on jwt.sub cannot express.
            _put(
                f"GROUP#{config.COGNITO_GROUP_RESEARCH}",
                "RATELIMIT",
                tokens_per_window={"N": str(config.DEMO_RATE_TOKENS_PER_WINDOW * 3)},
                requests_per_window={"N": str(config.DEMO_RATE_REQUESTS_PER_WINDOW * 3)},
                window_seconds={"N": str(config.DEMO_RATE_WINDOW_SECONDS)},
                pooled={"BOOL": True},
            ),
            # ---- BREAK GLASS: seeded OFF, and it must stay that way -----------
            # The interceptor is fail closed, which means an interceptor bug is a total
            # inference outage. That is only an acceptable trade if recovery is faster
            # than shipping code — so an administrator can flip this row and bypass
            # enforcement within the config cache TTL (~10s), no deployment.
            #
            # The row is SEEDED so its existence and shape are discoverable rather than
            # tribal knowledge; `enabled=false` is the safe state. Every bypassed request
            # writes an audit record at `decision=breakglass_bypass` carrying set_by and
            # reason, so turning it on is loud and attributable, and leaving it on is
            # visible in one Logs Insights query.
            _put(
                "DEFAULT",
                "BREAKGLASS",
                enabled={"BOOL": False},
                reason=_s("not active"),
                set_by=_s("cdk-seed"),
            ),
        ]

        seed = cr.AwsCustomResource(
            self,
            "GovernanceConfigSeed",
            # onCreate ONLY — see docstring. No on_update, so redeploys are safe.
            on_create=cr.AwsSdkCall(
                service="DynamoDB",
                action="batchWriteItem",
                physical_resource_id=cr.PhysicalResourceId.of("governance-config-seed"),
                parameters={"RequestItems": {table.table_name: seed_items}},
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["dynamodb:BatchWriteItem", "dynamodb:PutItem"],
                    resources=[table.table_arn],
                )
            ]),
            install_latest_aws_sdk=False,
        )
        seed.node.add_dependency(table)
        return table

    # ------------------------------------------------------------------ #
    def _build_guardrail_interceptor_fn(
        self,
        guardrail: bedrock.CfnGuardrail,
        ledger: dynamodb.Table,
        config_table: dynamodb.Table,
    ) -> _lambda.Function:
        """The REQUEST interceptor Lambda that enforces the guardrail on inference.

        Receives the raw (base64) request body, flattens the prompt text out of the
        Anthropic/OpenAI messages array (the thing native policy could NOT do,
        because the scalar guardrail data-path can't reach into a Set<record>),
        calls ApplyGuardrail, and short-circuits with 403 on intervention.
        """
        fn = _lambda.Function(
            self,
            "GuardrailInterceptorFn",
            function_name=f"{config.PREFIX}-guardrail-interceptor",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(_GUARDRAIL_LAMBDA_DIR),
            # HEADROOM, NOT A DEADLINE. Measured: when this function TIMES OUT the
            # gateway returns 200 and the model is invoked ungoverned (whereas an
            # unhandled exception fails closed with 400). So the function must never
            # actually reach its timeout — it enforces its OWN budget internally and
            # denies with 403 while it still has time to answer.
            #
            # This value therefore only has to be comfortably larger than the worst
            # honest path (config scan + rate + charge + ApplyGuardrail), so that the
            # internal deadline is always what fires first.
            timeout=Duration.seconds(config.INTERCEPTOR_TIMEOUT_SECONDS),
            memory_size=256,
            environment={
                "GUARDRAIL_ID": guardrail.attr_guardrail_id,
                "GUARDRAIL_VERSION": guardrail.attr_version,
                # How much budget the interceptor keeps in reserve so it can always emit
                # its own verdict instead of being killed mid-flight.
                "INTERCEPTOR_SAFETY_MARGIN_MS": str(config.INTERCEPTOR_SAFETY_MARGIN_MS),
                # Cross-surface model entitlement, enforced HERE for BOTH surfaces.
                # Match on substrings so one rule covers mantle's
                # `anthropic.claude-opus-5` and runtime's `us.anthropic.claude-opus-5`.
                # --- rate limits, the ONLY rate mechanism ------------------
                # Fallbacks only: the RATELIMIT rows in the config table are the
                # source of truth and can be changed at runtime.
                "RATE_TOKENS_PER_WINDOW": str(config.DEMO_RATE_TOKENS_PER_WINDOW),
                "RATE_REQUESTS_PER_WINDOW": str(config.DEMO_RATE_REQUESTS_PER_WINDOW),
                "RATE_WINDOW_SECONDS": str(config.DEMO_RATE_WINDOW_SECONDS),
                "PREMIUM_MODEL_MATCHES": ",".join([
                    config.MODELS.premium_qualified_model_id,   # anthropic.claude-opus-5
                    config.MODELS.runtime_premium_model,        # us.anthropic.claude-opus-5
                ]),
                # --- cross-surface COST governance -------------------------
                "COST_LEDGER_TABLE": ledger.table_name,
                "COST_BUDGET_USD": str(config.DEMO_COST_BUDGET_USD),
                "COST_WINDOW_SECONDS": str(config.DEMO_COST_WINDOW_SECONDS),
                # price per 1K input tokens, matched by model-id substring so one
                # entry covers the same model on both surfaces.
                "MODEL_PRICES_JSON": json.dumps(config.MODEL_INPUT_PRICES_PER_1K),
                # Output pricing is needed on the REQUEST side too, to RESERVE
                # worst-case generation cost from max_tokens before dispatch.
                "MODEL_OUTPUT_PRICES_JSON": json.dumps(config.MODEL_OUTPUT_PRICES_PER_1K),
                # --- governance policy data (runtime state) -----------------
                "CONFIG_TABLE": config_table.table_name,
                "CONFIG_CACHE_TTL_SECONDS": str(config.CONFIG_CACHE_TTL_SECONDS),
                # How long DECISION# records live = how far back the admin console can
                # look, because Statistics is computed entirely from them.
                "DECISION_RECORD_TTL_SECONDS": str(config.DECISION_RECORD_TTL_SECONDS),
                # --- central audit log -------------------------------------
                # Prompt CONTENT is off by default: an audit log is the wrong place
                # to concentrate the most sensitive data in the system. A SHA-256
                # plus length is always recorded, which is enough to correlate and
                # to detect tampering without retaining the text.
                "AUDIT_LOG_PROMPT_TEXT": str(config.AUDIT_LOG_PROMPT_TEXT).lower(),
                "AUDIT_LOG_PROMPT_MAX_CHARS": str(config.AUDIT_LOG_PROMPT_MAX_CHARS),
                "AUDIT_LOG_TOOL_SCHEMAS": str(config.AUDIT_LOG_TOOL_SCHEMAS).lower(),
                # --- real prices, refreshed daily -------------------------
                # The MODEL_PRICES_JSON constants above remain only as a fallback for
                # a model the Price List API does not publish.
                "PRICING_TABLE": self._pricing_table.table_name,
                "PRICING_CACHE_TTL_SECONDS": str(config.PRICING_CACHE_TTL_SECONDS),
                "PRICING_STALE_AFTER_SECONDS": str(config.PRICING_STALE_AFTER_SECONDS),
            },
            log_group=self._audit_log_group,
            description="Gateway REQUEST interceptor: guardrail + model entitlement + cost budget.",
        )
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ApplyGuardrail",
                effect=iam.Effect.ALLOW,
                actions=["bedrock:ApplyGuardrail"],
                resources=[guardrail.attr_guardrail_arn],
            )
        )
        ledger.grant_read_write_data(fn)
        config_table.grant_read_data(fn)
        # The interceptor may need to apply ANY guardrail the config table names,
        # not just the one this stack creates, so scope to account guardrails.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ApplyConfiguredGuardrails",
                effect=iam.Effect.ALLOW,
                actions=["bedrock:ApplyGuardrail"],
                resources=[
                    f"arn:aws:bedrock:*:{config.AWS_ACCOUNT}:guardrail/*",
                    f"arn:aws:bedrock:*:{config.AWS_ACCOUNT}:guardrail-profile/*",
                ],
            )
        )
        return fn

    # ------------------------------------------------------------------ #
    def _build_observability(self, gateway: agentcore.CfnGateway) -> dict:
        """Wire gateway logs + OTEL spans to CloudWatch (vended log delivery).

        WHY THIS MATTERS: the gateway signs every Bedrock call with ONE shared
        execution role, so Bedrock's own logs / CloudTrail can never distinguish
        end users. Per-user attribution has to come from the GATEWAY layer, which
        means gateway spans. Without this, there is no usage telemetry at all —
        which is also why `qualifiedModelId` had to be discovered by trial.

        Two layers are required and only the second is in this stack:

        1. **Account-level: CloudWatch Transaction Search must be ON** (X-Ray trace
           segment destination = CloudWatchLogs, plus a logs resource policy letting
           xray.amazonaws.com PutLogEvents to `aws/spans`). It is an account-wide
           setting with its own ingestion cost, so it is deliberately NOT created
           here — flipping a shared account setting from a demo stack would be
           rude. Enable it once per account:
               aws xray update-trace-segment-destination --destination CloudWatchLogs
           (console: CloudWatch > Application Signals > Transaction search).
           Tracing cannot be enabled on a gateway until this is done.

        2. **Per-gateway: vended log delivery** (this method). Two delivery
           SOURCES on the gateway ARN (APPLICATION_LOGS and TRACES), two
           DESTINATIONS (a CloudWatch log group for logs, XRAY for spans), and a
           DELIVERY joining each pair. Spans then land in the `aws/spans` log
           group, queryable with CloudWatch Logs Insights.

        Note the log group name must live under `/aws/vendedlogs/` for the CWL
        delivery destination to be writable without an extra resource policy.
        """
        gw_arn = gateway.attr_gateway_arn

        log_group = logs.LogGroup(
            self,
            "GatewayLogGroup",
            log_group_name=f"/aws/vendedlogs/bedrock-agentcore/{config.PREFIX}-gateway",
            retention=logs.RetentionDays.ONE_WEEK,   # demo-scale; raise for real use
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- delivery SOURCES (what to collect, from which resource) ---------
        logs_source = logs.CfnDeliverySource(
            self,
            "GatewayLogsSource",
            name=f"{config.PREFIX}-gateway-logs-source",
            log_type="APPLICATION_LOGS",
            resource_arn=gw_arn,
        )
        traces_source = logs.CfnDeliverySource(
            self,
            "GatewayTracesSource",
            name=f"{config.PREFIX}-gateway-traces-source",
            log_type="TRACES",
            resource_arn=gw_arn,
        )

        # --- delivery DESTINATIONS (where it goes) ---------------------------
        logs_destination = logs.CfnDeliveryDestination(
            self,
            "GatewayLogsDestination",
            name=f"{config.PREFIX}-gateway-logs-destination",
            delivery_destination_type="CWL",
            destination_resource_arn=log_group.log_group_arn,
        )
        # XRAY destination takes NO destination_resource_arn — spans are routed to
        # the account's span store (surfacing in the `aws/spans` log group because
        # Transaction Search sends trace segments to CloudWatch Logs).
        traces_destination = logs.CfnDeliveryDestination(
            self,
            "GatewayTracesDestination",
            name=f"{config.PREFIX}-gateway-traces-destination",
            delivery_destination_type="XRAY",
        )

        # --- DELIVERIES (join source -> destination) -------------------------
        logs_delivery = logs.CfnDelivery(
            self,
            "GatewayLogsDelivery",
            delivery_source_name=logs_source.name,
            delivery_destination_arn=logs_destination.attr_arn,
        )
        traces_delivery = logs.CfnDelivery(
            self,
            "GatewayTracesDelivery",
            delivery_source_name=traces_source.name,
            delivery_destination_arn=traces_destination.attr_arn,
        )

        for src in (logs_source, traces_source):
            src.add_dependency(gateway)
        logs_delivery.add_dependency(logs_source)
        logs_delivery.add_dependency(logs_destination)
        traces_delivery.add_dependency(traces_source)
        traces_delivery.add_dependency(traces_destination)

        return {
            "log_group": log_group,
            "logs_delivery": logs_delivery,
            "traces_delivery": traces_delivery,
        }

    # ------------------------------------------------------------------ #
    def _build_admin_console(self, gateway: agentcore.CfnGateway):
        """Governance admin console, fronted by CloudFront.

        Topology: ONE CloudFront distribution, two origins, path-routed.
          * `/`        → a PRIVATE S3 bucket holding the single-file SPA (OAC-locked,
                         no public access), served as a static object.
          * `/api/*`   → this Lambda behind an **API Gateway HTTP API** (the JSON API).

        Because the UI and the API answer on the SAME origin, there is no cross-origin
        request to permit and CORS is gone entirely (both the HTTP API preflight and the
        Lambda's `Access-Control-*` headers were removed). A `web_acl_id` can be attached
        to the distribution later to put WAF in front of the whole console.

        This replaces the earlier "one Lambda serves both the API and the HTML" design.
        Serving a UI by executing a Lambda is not a shape a customer would ship, and
        keeping the SPA and API on one Lambda forced the permissive CORS `*`. See
        `_build_admin_cdn` for the distribution.

        SECURITY POSTURE — stated plainly because it matters:
        the function is **NOT publicly invokable**. A Lambda Function URL was the first
        design and was removed: `authType=NONE` requires a resource policy with
        `Principal: "*"`, which made this function world-accessible and was flagged by
        account security tooling. (It also never worked here — an organization guardrail
        rejects unauthenticated Function URLs regardless of the resource policy.) The
        public surface is API Gateway; `pilot/guards.py` fails the synth if that ever
        regresses.

        There is deliberately no API Gateway JWT authorizer, because Cognito access
        tokens carry no `aud` claim. Every `/api/*` route is authorized IN CODE: the
        caller's Cognito access token is validated by calling `GetUser` with it (so
        Cognito itself proves the token is valid, unexpired and from our pool, with no
        hand-rolled JWKS verification), and the resolved username must belong to the
        admin group. The UI shell is public; no data is readable or writable without an
        admin token.

        This console is PRIVILEGED — it can widen model access and raise spend caps —
        so every mutation is logged with the acting admin. NOTE: those mutation records
        go to THIS function's own log group, not the shared governance audit log that
        the two interceptors write to. See docs/ADMIN-CONSOLE.md.
        """
        fn = _lambda.Function(
            self,
            "AdminConsoleFn",
            function_name=f"{config.PREFIX}-admin-console",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(_ADMIN_LAMBDA_DIR),
            timeout=Duration.seconds(60),   # span queries poll CloudWatch Logs Insights
            memory_size=512,
            environment={
                "CONFIG_TABLE": self._config_table.table_name,
                "COST_LEDGER_TABLE": self._cost_ledger.table_name,
                "USER_POOL_ID": self._cognito.user_pool.user_pool_id,
                "USER_POOL_CLIENT_ID": self._cognito.user_pool_client.user_pool_client_id,
                "ADMIN_GROUP": config.COGNITO_ADMIN_GROUP,
                "GATEWAY_ID": gateway.attr_gateway_identifier,
                "SPANS_LOG_GROUP": "aws/spans",
                # The console's history horizon, so the UI can state it and cap its own
                # time-range options instead of offering a range the data cannot cover.
                "DECISION_RECORD_TTL_SECONDS": str(config.DECISION_RECORD_TTL_SECONDS),
                # Where the durable copy lives, for the hand-off past that horizon.
                "AUDIT_LOG_GROUP": config.AUDIT_LOG_GROUP_NAME,
                "AUDIT_LOG_RETENTION_DAYS": str(config.audit_log_retention_days()),
                # Pricing table: model rates, for display.
                "PRICING_TABLE": self._pricing_table.table_name,
                # Per-user daily/monthly cost aggregates (out-of-band rollup) + the
                # sub->username map, so the console can look back past the 24h decision
                # TTL and label the live spend counters with names.
                "COST_ROLLUP_TABLE": self._cost_rollup_table.table_name,
                # The gateway's own URL, available to the console for display/links. (The
                # mantle catalog is fetched directly from the mantle service endpoint via
                # SigV4, not through the gateway — see _catalog / _mantle_models.)
                "GATEWAY_URL": gateway.attr_gateway_url,
                # The canonical model ids a MODELS glob is matched against, on BOTH
                # surfaces. Deliberately NOT derived from the pricing table: those keys
                # are normalized with punctuation stripped (`claudeopus5`), so evaluating
                # `*claude-opus*` against them reports the OPPOSITE verdict. The console's
                # effective-access preview uses these plus the ids observed in real
                # decision records.
                "GOVERNED_MODEL_IDS": ",".join([
                    config.MODELS.inference_model_id,        # bedrockprov/anthropic.claude-sonnet-5
                    config.MODELS.premium_model_id,          # bedrockprov/anthropic.claude-opus-5
                    # The target-qualified forms, as they appear once the inference
                    # router has stripped the target prefix.
                    config.MODELS.inference_model_id.split("/")[-1],
                    config.MODELS.premium_qualified_model_id,  # anthropic.claude-opus-5
                    config.MODELS.runtime_base_model,        # us.anthropic.claude-sonnet-5
                    config.MODELS.runtime_premium_model,     # us.anthropic.claude-opus-5
                ]),
            },
            description="Governance admin console (API + UI): model access, cost, guardrails, stats.",
        )

        # Policy data: read AND write (this is the console's whole purpose).
        self._config_table.grant_read_write_data(fn)
        # Spend ledger: read only — the console reports spend, it does not adjust it.
        self._cost_ledger.grant_read_data(fn)

        # Model inventory for the model picker and the effective-access preview. The
        # pricing table already holds one row per model this deployment can price, so it
        # doubles as the list of models it can govern.
        self._pricing_table.grant_read_data(fn)
        # Cost rollup: per-user daily/monthly aggregates + the sub->username map.
        self._cost_rollup_table.grant_read_data(fn)
        # Live Bedrock model catalog for the pickers, from BOTH surfaces:
        #   * runtime — bedrock:ListInferenceProfiles (+ ListFoundationModels fallback).
        #   * mantle  — a SigV4-signed GET to bedrock-mantle.<region>.api.aws/v1/models.
        #     Mantle is a DISTINCT IAM service namespace (`bedrock-mantle:*`); the gateway
        #     role gets it via the AmazonBedrockMantleInferenceAccess managed policy. The
        #     console needs only the list call, granted narrowly here. None of these
        #     actions are resource-scopable.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadBedrockModelCatalog",
                effect=iam.Effect.ALLOW,
                actions=["bedrock:ListFoundationModels",
                         "bedrock:ListInferenceProfiles",
                         "bedrock-mantle:ListModels"],
                resources=["*"],
            )
        )

        # Group membership for authorization, PLUS the identity pickers. A free-text
        # scope box accepts `GROUP#ml-reserch` and produces a rule that silently never
        # matches, which is the worst kind of governance bug — the console displays
        # policy that does not exist. Listing real users and groups removes the class.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadCognitoIdentitiesForPickers",
                effect=iam.Effect.ALLOW,
                actions=[
                    "cognito-idp:AdminListGroupsForUser",
                    "cognito-idp:ListUsers",
                    "cognito-idp:ListGroups",
                ],
                resources=[self._cognito.user_pool.user_pool_arn],
            )
        )
        # Guardrail picker + configuration preview, so an admin can see what a guardrail
        # actually enforces before binding a group to it. Read-only.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadGuardrailsForPicker",
                effect=iam.Effect.ALLOW,
                actions=["bedrock:ListGuardrails", "bedrock:GetGuardrail"],
                resources=["*"],  # ListGuardrails is not resource-scopable
            )
        )
        # Enforcement statistics from gateway spans.
        fn.add_to_role_policy(
            iam.PolicyStatement(
                sid="QueryGatewaySpans",
                effect=iam.Effect.ALLOW,
                actions=[
                    "logs:StartQuery",
                    "logs:GetQueryResults",
                    "logs:DescribeLogGroups",
                ],
                resources=["*"],  # Logs Insights StartQuery requires wildcard scope
            )
        )

        # FINDING: a Lambda **Function URL** was the first choice (fewest moving
        # parts) but does not work in this account. With `authType=NONE` and a
        # textbook-correct resource policy in place —
        #   Principal "*", Action lambda:InvokeFunctionUrl,
        #   Condition lambda:FunctionUrlAuthType = NONE
        # — every request, including the plain UI shell, still returned
        #   403 {"Message":"Forbidden. For troubleshooting Function URL authorization..."}
        # i.e. rejected by the Function URL auth layer before our code ran. Since the
        # policy was provably correct, the cause is almost certainly an
        # organization-level guardrail (SCP/RCP) forbidding unauthenticated Lambda
        # Function URLs. Not something to fight from a demo stack.
        #
        # An API Gateway **HTTP API** is used instead: it is conventional for an admin
        # console, its payload format (2.0) is identical to the Function URL event
        # shape (`requestContext.http.method` / `.path`), so the handler needed no
        # changes, and it is not subject to that guardrail.
        #
        # No JWT authorizer is attached, deliberately: authorization stays in the
        # Lambda, which validates the Cognito ACCESS token via GetUser and then checks
        # admin-group membership. Cognito access tokens carry no `aud` claim (a finding
        # from earlier in this pilot), which makes them awkward for the built-in JWT
        # authorizer — and doing it in code keeps the group check in one place.
        #
        # NO CORS on the HTTP API. The SPA and this API are served from the SAME
        # CloudFront distribution (below), so every /api/* call is same-origin. The
        # previous `allow_origins=["*"]` preflight was a gap, not a requirement, and is
        # removed with it.
        api = apigw.HttpApi(
            self,
            "AdminConsoleApi",
            api_name=f"{config.PREFIX}-admin-console",
            default_integration=apigw_int.HttpLambdaIntegration("AdminIntegration", fn),
        )

        distribution = self._build_admin_cdn(api)
        return fn, api, distribution

    # ------------------------------------------------------------------ #
    def _build_admin_cdn(self, api: apigw.HttpApi) -> cloudfront.Distribution:
        """Serve the console from CloudFront: SPA from a PRIVATE S3 bucket, JSON API
        from the HTTP API — both on ONE distribution, path-routed.

        This is the production shape the earlier single-Lambda design deferred. It buys
        three things at once:

          * the SPA is a static object in a private bucket (locked to CloudFront via an
            Origin Access Control), so the UI is no longer served by executing a Lambda;
          * the API and the UI share one origin, which is why CORS could be deleted
            outright rather than narrowed;
          * a `web_acl_id` can be attached to this distribution later to put WAF in
            front of the whole console — no code change beyond that one property.

        The public surface is CloudFront, never the Lambda — which is the rule
        `pilot/guards.py` exists to enforce. No Lambda Function URL is introduced, so
        that guard is unaffected.
        """
        # Private bucket for the single-page app. No public access; CloudFront reaches
        # it through an Origin Access Control (OAC), so the only path to these objects
        # is the distribution.
        ui_bucket = s3.Bucket(
            self,
            "AdminConsoleUiBucket",
            bucket_name=f"{config.PREFIX}-admin-console-ui-{self.account}",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,   # demo stack: tears down cleanly
            auto_delete_objects=True,
        )

        # The SPA is the SAME single-file HTML the Lambda used to serve, now shipped as
        # a static object. It is fully self-contained and origin-agnostic: it reads
        # region + Cognito client id from GET /api/meta at load time (there is no
        # server-side templating step any more). Sourced straight from the handler
        # module's `_UI_HTML` constant so there is exactly one copy of the UI.
        ui_html = _load_admin_ui_html()
        s3_deployment.BucketDeployment(
            self,
            "AdminConsoleUiDeployment",
            destination_bucket=ui_bucket,
            sources=[s3_deployment.Source.data("index.html", ui_html)],
            # index.html must not be cached hard, so a redeploy of the UI is visible
            # without a manual invalidation; the SPA itself pulls fresh /api data.
            cache_control=[
                s3_deployment.CacheControl.set_public(),
                s3_deployment.CacheControl.max_age(Duration.seconds(60)),
            ],
        )

        # The HTTP API endpoint is a full URL (https://<id>.execute-api.<region>...);
        # an HttpOrigin wants the bare domain, so strip the scheme.
        api_domain = Fn.select(2, Fn.split("/", api.api_endpoint))

        distribution = cloudfront.Distribution(
            self,
            "AdminConsoleDistribution",
            comment=f"{config.PREFIX} governance admin console",
            default_root_object="index.html",
            # Default behaviour: the SPA, from the private S3 bucket via OAC.
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront_origins.S3BucketOrigin.with_origin_access_control(
                    ui_bucket
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            additional_behaviors={
                # The JSON API, from the HTTP API origin. Nothing here is cacheable
                # (every response is per-request, token-authorized), and the viewer's
                # Authorization header MUST reach the origin — ALL_VIEWER_EXCEPT_HOST_HEADER
                # forwards headers/query/cookies but drops Host, which an HttpOrigin
                # requires so it presents the API Gateway's own host.
                "/api/*": cloudfront.BehaviorOptions(
                    origin=cloudfront_origins.HttpOrigin(api_domain),
                    viewer_protocol_policy=(
                        cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
                    ),
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=(
                        cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER
                    ),
                ),
            },
            # web_acl_id intentionally unset. A WAF web ACL (CfnWebACL, scope=CLOUDFRONT,
            # created in us-east-1) can be attached here later without any other change.
        )
        return distribution

    # ------------------------------------------------------------------ #
    def _build_policy_engine(self) -> agentcore.CfnPolicyEngine:
        """Cedar policy engine. Holds the per-group model-access policy."""
        return agentcore.CfnPolicyEngine(
            self,
            "PolicyEngine",
            # Policy/engine Name must match ^[A-Za-z][A-Za-z0-9_]*$ (NO hyphens).
            name="acgw_pilot_policy_engine",
            description="Cedar policy engine for the inference-governance pilot.",
        )

    # ------------------------------------------------------------------ #
    # DELETED: _build_rate_limit (native per-user TPM on $.context.jwt.sub).
    #
    # It worked, and it is still worth knowing it exists — but it could not be part of a
    # cross-surface governance plane:
    #
    #   * it attaches only on recognised inference paths, so the bedrock-runtime
    #     passthrough target was never metered by it;
    #   * it meters INPUT tokens only, so it cannot bound generation spend;
    #   * it keys on a scalar claim, so it can express "500 tokens each" but never
    #     "3,000 tokens shared by the ml-research team".
    #
    # The interceptor's RATELIMIT config kind replaces it on all three counts. Keeping
    # both meant one surface had a backstop and the other did not, which is a misleading
    # kind of safety. See docs/FINDINGS.md.
    # ------------------------------------------------------------------ #
    def _build_group_access_policy(
        self, engine: agentcore.CfnPolicyEngine, gateway: agentcore.CfnGateway
    ) -> agentcore.CfnPolicy:
        """Cedar policy: may this caller use the gateway AT ALL? One boolean.

        SCOPE, stated precisely because it is easy to overestimate. Cedar governs
        exactly one question here — membership of the platform group — and nothing
        else. It does NOT govern which model you may use, how fast, or how much you
        may spend. Those are interceptor controls reading the config table.

        WHY IT IS STILL HERE, now that the interceptor is the basis of enforcement:
        Cedar is the only enforcement path that does not depend on our code or on a
        Lambda finishing in time. No Python, no DynamoDB read, no ApplyGuardrail call,
        no invocation budget. Given that a REQUEST-interceptor TIMEOUT was measured to
        fail OPEN at the gateway (see docs/FINDINGS.md), an independent check that
        cannot time out is worth more, not less. And unlike the native rate limits that
        were deleted, this one applies on BOTH surfaces — verified: a non-member gets
        403 on mantle and on the runtime passthrough.

        So the division of labour is: Cedar answers "are you allowed in", cheaply and
        independently; the interceptor answers everything expressive.

        TWO HONEST WEAKNESSES, both recorded in docs/FINDINGS.md:

        1. Denials here are NOT attributable in the audit log. The interceptor runs
           BEFORE Cedar, so a non-member's request is recorded as `allowed` by the
           interceptor and the actual denial surfaces only as an unattributed 403 at
           the RESPONSE stage. The audit log is complete for interceptor-enforced
           controls and partial for group authorization.

        2. The membership test is a SUBSTRING match (see `forbid_stmt` below), so a
           group whose name merely CONTAINS the platform group name would satisfy it.
           Acceptable with three demo groups; NOT something to copy into an enterprise
           directory without tightening.
        """
        # FINDING (empirical): the gateway's Cedar schema exposes an InvokeLLM action but
        # does NOT surface `context.input.model` for it, so per-MODEL access cannot be
        # expressed in Cedar at all. JWT claims arrive as principal TAGS, not attributes.
        # That constraint is the entire reason model entitlement lives in the interceptor.
        # A constrained action (== InvokeLLM) requires a constrained resource
        # (the specific gateway ARN, not the AgentCore::Gateway type).
        gw_arn = gateway.attr_gateway_arn
        # FINDING: for an INFERENCE target, the Cedar action IS the target name
        # itself ("bedrock") — not TargetName___op. (MCP targets use
        # Target___tool per tool; inference targets expose a single action = the
        # target.) The schema error explicitly said: did you mean
        # AgentCore::Action::"bedrock"?
        # Use a POSITIVE `when` (forbid only principals explicitly in the
        # standard group) rather than `unless premium`. The `unless` form tripped
        # the engine's "Overly Restrictive" guard because principal types without
        # a cognito:groups tag (IamEntity, unauthenticated) would be denied
        # unconditionally. Forbidding only the standard group is well-scoped.
        # FINDING: once ANY policy exists, the engine is DENY-BY-DEFAULT — an
        # explicit `permit` is required to allow. (With no policy it permits;
        # verified.) So the policy set is: PERMIT OAuthUsers to invoke bedrock,
        # then FORBID the standard group. Cedar `forbid` overrides `permit`, so
        # premium is permitted and standard is denied.
        # validation_mode=IGNORE_ALL_FINDINGS bypasses the deploy-time
        # "overly restrictive" static analyzer; enforcement is validated at runtime.
        # NOTE: one CfnPolicy = exactly one Cedar statement. So the permit and
        # the forbid are TWO separate policies on the same engine.
        # IMPORTANT: validation accepts the parent action "bedrock", but at
        # RUNTIME the request action is the HTTP-suffixed child (e.g.
        # "bedrock___POST:/v1/messages"). A permit scoped to == "bedrock" won't
        # match at runtime -> "no policy applies". So the PERMIT leaves the action
        # UNCONSTRAINED (any action on this gateway for OAuthUsers), and the
        # FORBID narrows the standard group. forbid overrides permit in Cedar.
        permit_stmt = (
            'permit(\n'
            '  principal is AgentCore::OAuthUser,\n'
            '  action,\n'
            f'  resource == AgentCore::Gateway::"{gw_arn}"\n'
            ');'
        )
        # THE ONE CONTROL CEDAR OWNS: forbid inference for principals that are NOT in
        # the platform group. The forbid fires when the group is absent from the tag (or
        # the tag is missing entirely) -> carol (no group) is denied entry; alice and bob
        # pass and go on to be governed by the interceptor.
        #
        # ⚠️ KNOWN WEAKNESS — SUBSTRING MATCHING. `cognito:groups` is multi-valued and
        # Cedar renders it as an opaque scalar, so `==` and `.contains` both proved
        # unreliable against it and this settled on a `like` wildcard. The consequence is
        # that the test is a SUBSTRING match, not set membership: a group named
        # `former-ai-platform-users` or `no-ai-platform-access` would ALSO satisfy
        # `like "*ai-platform*"` and be admitted.
        #
        # Risk is negligible with three demo groups whose names we control, and the blast
        # radius is bounded — passing this check only gets you to the interceptor, which
        # still decides models, rate and spend. But it is a real authorization defect and
        # must not be copied into an environment with a large or externally-managed group
        # directory. Tightening it means either finding a reliable exact-match form
        # against the multi-valued tag, or mapping groups to a scalar claim minted at
        # token issue (which is what the deleted `tier` claim did, and why it existed).
        # Recorded in docs/FINDINGS.md rather than left as a comment nobody reads.
        forbid_stmt = (
            'forbid(\n'
            '  principal is AgentCore::OAuthUser,\n'
            '  action,\n'
            f'  resource == AgentCore::Gateway::"{gw_arn}"\n'
            ')\n'
            'unless {\n'
            f'  principal.hasTag("cognito:groups") &&\n'
            f'  principal.getTag("cognito:groups") like "*{config.COGNITO_GROUP_PLATFORM}*"\n'
            '};'
        )

        permit_policy = agentcore.CfnPolicy(
            self,
            "InferencePermitPolicy",
            policy_engine_id=engine.attr_policy_engine_id,
            name="acgw_pilot_inference_permit",
            definition=agentcore.CfnPolicy.PolicyDefinitionProperty(
                cedar=agentcore.CfnPolicy.CedarPolicyProperty(statement=permit_stmt),
            ),
            validation_mode="IGNORE_ALL_FINDINGS",
            description="Permit OAuthUsers to invoke the bedrock inference action (baseline allow).",
        )
        permit_policy.add_dependency(engine)
        permit_policy.add_dependency(gateway)

        # NAME AND DESCRIPTION CORRECTED. This was `acgw_pilot_model_access`, described as
        # forbidding "the standard cognito group" — both wrong, and misleading in exactly
        # the place it matters, because the policy name is what the console shows.
        #
        #   * it governs GROUP MEMBERSHIP, not model access. Per-model entitlement is an
        #     interceptor control (Cedar *can* express it on mantle child actions, but this
        #     policy does not, and it could not cover the runtime passthrough).
        #   * there is no "standard" group any more; the tier axis was deleted. It forbids
        #     principals that are NOT in the platform group.
        #
        # The builder was renamed to `_build_group_access_policy` long ago; the resource
        # name and construct id were missed. Renaming both REPLACES the policy: CFN creates
        # the new one before deleting the old, so there is a brief window with two identical
        # forbids, which is harmless. Policy writes are asynchronous (CREATING -> ACTIVE),
        # so verify enforcement after deploying rather than assuming.
        forbid_policy = agentcore.CfnPolicy(
            self,
            "GroupAccessPolicy",
            policy_engine_id=engine.attr_policy_engine_id,
            name="acgw_pilot_group_access",
            definition=agentcore.CfnPolicy.PolicyDefinitionProperty(
                cedar=agentcore.CfnPolicy.CedarPolicyProperty(statement=forbid_stmt),
            ),
            # Forbid overrides permit in Cedar, so this narrows the baseline allow.
            validation_mode="IGNORE_ALL_FINDINGS",
            description=("Forbid principals that are NOT members of the "
                         f"{config.COGNITO_GROUP_PLATFORM} group from using gateway "
                         "inference. Governs gateway entry only, not model choice."),
        )
        forbid_policy.add_dependency(engine)
        forbid_policy.add_dependency(gateway)
        return forbid_policy

    # ------------------------------------------------------------------ #
    def _build_guardrail_policy(
        self, engine: agentcore.CfnPolicyEngine, gateway: agentcore.CfnGateway
    ) -> agentcore.CfnPolicy:
        """Guardrail-in-policy on the inference action (the unified-enforcement probe).

        Confirmed by docs: guardrails run on HTTP INFERENCE targets (POST /inference).
        The BedrockGuardrails:: functions are built-in (call InvokeGuardrailChecks via
        the gateway role's FAS creds) — no provisioned Guardrail resource needed.

        This forbids inference when a PROMPT_ATTACK (prompt injection) is detected
        in the request content. The `when guardrails {}` block replaces standard
        Cedar `when {}` (they cannot be mixed).

        EMPIRICAL UNKNOWN under test: the correct dataPath into the Anthropic
        Messages body. Docs use context.input.prompt / context.input.message for
        other targets; whether the inference action exposes the prompt at that
        path is exactly what this probe validates. Start with context.input.prompt.
        """
        gw_arn = gateway.attr_gateway_arn
        # Scope the action to the PROVIDER inference target ("bedrockprov").
        # EXPERIMENT: the connector target ("bedrock") declares no input schema,
        # so context.input.prompt/.body were "not present". A provider target
        # declares operations/paths/models explicitly — this tests whether that
        # surfaces the request content to the guardrail. Constraining action
        # requires a concrete resource (the gateway ARN), same as model-access.
        # KEY CORRECTION (from the guardrails-in-policies doc + the deploy error):
        #  1. The guardrail must be scoped to the CHILD HTTP action
        #     "<TargetName>___POST:/<path>", NOT the bare target name. The bare
        #     parent action declares no request-body fields, so any body path is
        #     "not present". The doc example: action == "<TargetName>___POST:/invocations".
        #  2. context.input fields are the OPERATION's request-body fields (per the
        #     Memory FGAC doc: context.input = path params + body fields from the
        #     operation schema). For the Anthropic Messages op (/v1/messages) the
        #     body's top-level field is `messages` — not `prompt`/`body`. The doc's
        #     dataPath examples are context.input.message / context.input.systemPrompt.
        # So scope to bedrockprov___POST:/v1/messages and reference a STRING body field.
        #
        # BREAKTHROUGH (empirical, deploy #2): context.input.messages RESOLVED on
        # this provider action (typed `Set<record>`) — i.e. the provider target DOES
        # surface the request body to the guardrail context (the connector did not).
        # The remaining constraint: PromptAttack takes a scalar `string`, but
        # `messages` is an array of records. So we must reference a STRING-typed
        # body field. In the Anthropic Messages schema the top-level string field
        # is `system` (the system prompt). Reference context.input.system.
        provider_action = (
            f"{config.MODELS.provider_target_name}___POST:{config.MODELS.provider_op_path}"
        )
        cedar = (
            'forbid(\n'
            '  principal is AgentCore::OAuthUser,\n'
            f'  action == AgentCore::Action::"{provider_action}",\n'
            f'  resource == AgentCore::Gateway::"{gw_arn}"\n'
            ')\n'
            'when guardrails {\n'
            '  BedrockGuardrails::PromptAttack(["PROMPT_INJECTION"], [context.input.messages.content])'
            '["PROMPT_INJECTION"].confidenceScore.greaterThan(decimal("0.4"))\n'
            '};'
        )
        policy = agentcore.CfnPolicy(
            self,
            "GuardrailPolicy",
            policy_engine_id=engine.attr_policy_engine_id,
            name="acgw_pilot_guardrail",
            definition=agentcore.CfnPolicy.PolicyDefinitionProperty(
                # The `policy` field (not `cedar`) accepts the AgentCore policy
                # superset — Cedar + temporal + `when guardrails {}`. The plain
                # `cedar` field rejects the `guardrails` token.
                policy=agentcore.CfnPolicy.PolicyStatementProperty(statement=cedar),
            ),
            validation_mode="IGNORE_ALL_FINDINGS",
            description="Forbid inference when a prompt-injection attack is detected (guardrail-in-policy).",
        )
        policy.add_dependency(engine)
        policy.add_dependency(gateway)
        return policy

    # ------------------------------------------------------------------ #
    def _outputs(self) -> None:
        CfnOutput(self, "GatewayId", value=self._gateway.attr_gateway_identifier)
        CfnOutput(self, "GatewayArn", value=self._gateway.attr_gateway_arn)
        CfnOutput(self, "GatewayUrl", value=self._gateway.attr_gateway_url)
        CfnOutput(
            self,
            "GatewayExecutionRoleArn",
            value=self._gateway_role.role_arn,
        )
        # Clients set base_url = <GatewayUrl>/inference/v1 (append /chat/completions etc.).
        CfnOutput(
            self,
            "InferenceBaseUrlHint",
            value=f"{self._gateway.attr_gateway_url}/inference/v1",
            description="OpenAI-style base_url for clients (Anthropic path: /inference/v1/messages).",
        )
        CfnOutput(self, "GuardrailId", value=self._guardrail.attr_guardrail_id)
        CfnOutput(
            self,
            "GuardrailInterceptorFnName",
            value=self._guardrail_fn.function_name,
        )
        # Stable, stack-level Cognito outputs so clients can auto-discover the pool
        # and app client after ANY deploy. (The CognitoIdentity construct also emits
        # its own outputs, but nested-construct output keys carry a generated hash
        # suffix — e.g. Cognito2UserPoolIdB2475321 — which is not safe to look up
        # by name. These two keys are fixed.)
        CfnOutput(
            self,
            "UserPoolId",
            value=self._cognito.user_pool.user_pool_id,
            description="Cognito user pool id (stable key for client auto-discovery).",
        )
        CfnOutput(
            self,
            "UserPoolClientId",
            value=self._cognito.user_pool_client.user_pool_client_id,
            description="Cognito app client id (stable key for client auto-discovery).",
        )
        CfnOutput(
            self,
            "GatewayLogGroupName",
            value=self._observability["log_group"].log_group_name,
            description="Gateway application logs (spans go to the aws/spans log group).",
        )
        CfnOutput(
            self,
            "AdminConsoleUrl",
            value=f"https://{self._admin_distribution.distribution_domain_name}",
            description=("Governance admin console (CloudFront). Sign in with the "
                         "gateway-admins user."),
        )
        CfnOutput(
            self,
            "ModelPricingTable",
            value=self._pricing_table.table_name,
            description=("Bedrock token rates refreshed daily from the AWS Price List "
                         "API. Row _META carries the last refresh time."),
        )
        CfnOutput(
            self,
            "AuditLogGroupName",
            value=self._audit_log_group.log_group_name,
            description=("Single searchable governance audit log (both interceptors). "
                         "Query with CloudWatch Logs Insights: filter audit = 1"),
        )
        CfnOutput(
            self,
            "GovernanceConfigTable",
            value=self._config_table.table_name,
            description="DynamoDB table holding governance policy data (runtime state).",
        )
        CfnOutput(
            self,
            "CostRollupTable",
            value=self._cost_rollup_table.table_name,
            description=("Per-user daily/monthly cost aggregates, written out-of-band by "
                         "the cost-rollup Lambda (not the interceptors)."),
        )
