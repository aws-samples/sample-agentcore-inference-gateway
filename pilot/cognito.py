"""Cognito user pool for the AgentCore Gateway inference pilot.

Self-contained IdP (CDK-provisioned) with ONE identity axis: **group membership**.

Group membership answers two different governance questions through two different
mechanisms, which is the part worth internalizing:

  * "May you use inference at all?"  -> Cedar policy on `cognito:groups`
  * "Which models, how fast, how much?" -> the governance config table, on
    `GROUP#<name>` and `USER#<name>` scopes read by the interceptor

`tier` HAS BEEN REMOVED. It existed only because a native gateway rate limit needs a
SCALAR claim to key on while `cognito:groups` is multi-valued — so a single-value
`tier` claim was invented, along with a pre-token-generation Lambda (V2_0) to inject it
into the access token and the ESSENTIALS feature plan to permit that injection. Once
the native tier/model limit was deleted and rate limiting moved into the interceptor,
tier had no job left. Deleting it also deleted the trigger Lambda and the ESSENTIALS
requirement — the pool runs on LITE now.

Login is browser-free USER_PASSWORD_AUTH.

Demo users:
  alice — ai-platform + ml-research -> allowed in; research policy clears premium
  bob   — ai-platform               -> allowed in; default policy denies premium
  carol — no groups                 -> denied entry entirely by Cedar
"""
from constructs import Construct
from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    aws_cognito as cognito,
    custom_resources as cr,
)

from . import config


class CognitoIdentity(Construct):
    def __init__(self, scope: Construct, construct_id: str) -> None:
        super().__init__(scope, construct_id)

        # --- User pool -------------------------------------------------------
        # No custom attributes and no pre-token trigger, so no ESSENTIALS plan: the
        # only claims governance needs (`cognito:groups`, `sub`, `username`) are in a
        # standard access token already.
        self.user_pool = cognito.UserPool(
            self,
            "UserPool",
            user_pool_name=config.COGNITO_POOL_NAME,
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(username=True, email=True),
            feature_plan=cognito.FeaturePlan.LITE,
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- App client: USER_PASSWORD_AUTH, no secret ----------------------
        self.user_pool_client = cognito.UserPoolClient(
            self,
            "UserPoolClient",
            user_pool=self.user_pool,
            user_pool_client_name=config.COGNITO_CLIENT_NAME,
            generate_secret=False,
            auth_flows=cognito.AuthFlow(user_password=True, user_srp=True),
            access_token_validity=Duration.hours(1),
            id_token_validity=Duration.hours(1),
            refresh_token_validity=Duration.days(30),
            prevent_user_existence_errors=True,
        )

        # --- Groups: the ONE identity axis ----------------------------------
        groups = {}
        for idx, (gname, (cid, _suffix, gdesc)) in enumerate(config.COGNITO_GROUPS.items()):
            groups[gname] = cognito.CfnUserPoolGroup(
                self,
                cid,   # pinned construct id — see config.COGNITO_GROUPS
                user_pool_id=self.user_pool.user_pool_id,
                group_name=gname,
                description=gdesc,
                precedence=idx + 1,
            )

        # --- Sample users (driven by config.COGNITO_USERS) ------------------
        for uname, spec in config.COGNITO_USERS.items():
            cap = uname.capitalize()
            user = cognito.CfnUserPoolUser(
                self,
                f"User{cap}",
                user_pool_id=self.user_pool.user_pool_id,
                username=uname,
                message_action="SUPPRESS",
                user_attributes=[
                    cognito.CfnUserPoolUser.AttributeTypeProperty(name="email", value=spec["email"]),
                    cognito.CfnUserPoolUser.AttributeTypeProperty(name="email_verified", value="true"),
                ],
            )

            # Group membership is the whole of this user's governance identity.
            for gname in spec["groups"]:
                suffix = config.COGNITO_GROUPS[gname][1]
                member = cognito.CfnUserPoolUserToGroupAttachment(
                    self,
                    f"{cap}{suffix}",   # pinned — see config.COGNITO_GROUPS
                    user_pool_id=self.user_pool.user_pool_id,
                    group_name=gname,
                    username=uname,
                )
                member.add_dependency(groups[gname])
                member.add_dependency(user)

            # Permanent password so USER_PASSWORD_AUTH works without a challenge.
            setpw = cr.AwsCustomResource(
                self,
                f"SetPw{cap}",
                on_create=cr.AwsSdkCall(
                    service="CognitoIdentityServiceProvider",
                    action="adminSetUserPassword",
                    parameters={
                        "UserPoolId": self.user_pool.user_pool_id,
                        "Username": uname,
                        "Password": config.COGNITO_DEMO_PASSWORD,
                        "Permanent": True,
                    },
                    physical_resource_id=cr.PhysicalResourceId.of(f"setpw-{uname}"),
                ),
                policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                    resources=[self.user_pool.user_pool_arn]
                ),
            )
            setpw.node.add_dependency(user)

        # --- Admin identity for the governance console -----------------------
        # Separate from the inference users on purpose: an admin who can widen model
        # access and raise spend caps should be attributable, and does NOT get
        # inference access (no ai-platform membership) just for being an admin.
        admin_group = cognito.CfnUserPoolGroup(
            self,
            "AdminGroup",
            user_pool_id=self.user_pool.user_pool_id,
            group_name=config.COGNITO_ADMIN_GROUP,
            description="Members may administer governance policy via the admin console.",
            precedence=0,
        )
        admin_user = cognito.CfnUserPoolUser(
            self,
            "AdminUser",
            user_pool_id=self.user_pool.user_pool_id,
            username=config.COGNITO_ADMIN_USER,
            message_action="SUPPRESS",
            user_attributes=[
                cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="email", value="admin@example.com"
                ),
                cognito.CfnUserPoolUser.AttributeTypeProperty(
                    name="email_verified", value="true"
                ),
            ],
        )
        admin_member = cognito.CfnUserPoolUserToGroupAttachment(
            self,
            "AdminInAdmins",
            user_pool_id=self.user_pool.user_pool_id,
            group_name=config.COGNITO_ADMIN_GROUP,
            username=config.COGNITO_ADMIN_USER,
        )
        admin_member.add_dependency(admin_group)
        admin_member.add_dependency(admin_user)

        admin_pw = cr.AwsCustomResource(
            self,
            "SetPwAdmin",
            on_create=cr.AwsSdkCall(
                service="CognitoIdentityServiceProvider",
                action="adminSetUserPassword",
                parameters={
                    "UserPoolId": self.user_pool.user_pool_id,
                    "Username": config.COGNITO_ADMIN_USER,
                    "Password": config.COGNITO_ADMIN_PASSWORD,
                    "Permanent": True,
                },
                physical_resource_id=cr.PhysicalResourceId.of("setpw-admin"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=[self.user_pool.user_pool_arn]
            ),
        )
        admin_pw.node.add_dependency(admin_user)

        # --- Outputs ---------------------------------------------------------
        CfnOutput(self, "UserPoolId", value=self.user_pool.user_pool_id)
        CfnOutput(self, "UserPoolClientId", value=self.user_pool_client.user_pool_client_id)
        CfnOutput(
            self,
            "CognitoDiscoveryUrl",
            value=config.cognito_discovery_url(config.AWS_REGION, self.user_pool.user_pool_id),
        )
        CfnOutput(self, "CognitoIssuer", value=config.cognito_issuer(config.AWS_REGION, self.user_pool.user_pool_id))
        # Demo passwords are supplied via env var or randomly generated at synth (never
        # hardcoded in source). Surface them here so a deployer can retrieve the value for
        # the manual admin-console login and the notebook. These are throwaway credentials
        # for a pool destroyed with the stack; do not adopt this output pattern for a real
        # password — use Secrets Manager and a forced password reset on first sign-in.
        CfnOutput(self, "DemoUserPassword", value=config.COGNITO_DEMO_PASSWORD,
                  description="Password for demo inference users (alice/bob/carol). Demo-only.")
        CfnOutput(self, "AdminUserPassword", value=config.COGNITO_ADMIN_PASSWORD,
                  description="Password for the admin console user (gwadmin). Demo-only.")
