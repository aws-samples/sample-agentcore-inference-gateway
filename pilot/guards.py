"""Synth-time security guards (CDK Aspects).

WHY THIS FILE EXISTS
--------------------
A Lambda in this stack was briefly world-accessible. The admin console was first built
on a Lambda **Function URL** with `authType=NONE`, which requires a resource policy with
`Principal: "*"`. That was detected by account tooling and auto-mitigated, and the code
has since moved to an API Gateway HTTP API — but "we removed it" is a weaker guarantee
than "it cannot be deployed".

These aspects fail the synth if a public Lambda surface is ever reintroduced, so the
regression is caught locally rather than by a security detector after deployment.

WHAT IS CHECKED
  1. No Lambda resource-policy statement with `Principal: "*"` (or `{"AWS": "*"}`).
  2. No Lambda Function URL with `AuthType: NONE`.
  3. Every Lambda invoke permission for a service principal must be constrained by
     `SourceArn` / `SourceAccount`, so a service cannot be used as an open door.

Rule 3 is a warning rather than an error: there are legitimate cases where the source
ARN is genuinely unknown at synth time, and a hard failure there would be wrong.
"""
import jsii
from aws_cdk import Annotations, IAspect
from aws_cdk import aws_lambda as _lambda
from constructs import IConstruct


def _is_wildcard_principal(principal) -> bool:
    """True for `*` in any of the shapes CloudFormation accepts."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


@jsii.implements(IAspect)
class NoPublicLambdaAspect:
    """Fail synth if any Lambda in scope is publicly invokable."""

    def visit(self, node: IConstruct) -> None:
        # --- 1 & 3: resource-policy permissions --------------------------------
        if isinstance(node, _lambda.CfnPermission):
            if _is_wildcard_principal(node.principal):
                Annotations.of(node).add_error(
                    "SECURITY: Lambda permission grants Principal '*', which makes the "
                    "function world-accessible. Scope it to a specific principal, or "
                    "front the function with API Gateway and authorize in code. "
                    "(This exact pattern was previously flagged and auto-mitigated in "
                    "the deployment account.)"
                )
            principal = node.principal
            is_service = isinstance(principal, str) and principal.endswith(".amazonaws.com")
            if is_service and not (node.source_arn or node.source_account):
                Annotations.of(node).add_warning(
                    f"Lambda permission for service principal '{principal}' has no "
                    "SourceArn/SourceAccount condition, so any caller in that service "
                    "(including other accounts) could invoke it. Scope it if the source "
                    "is known at synth time."
                )

        # --- 2: Function URLs --------------------------------------------------
        if isinstance(node, _lambda.CfnUrl):
            if str(node.auth_type).upper() == "NONE":
                Annotations.of(node).add_error(
                    "SECURITY: Lambda Function URL uses AuthType NONE, which exposes the "
                    "function to the public internet and requires a wildcard resource "
                    "policy. Use AWS_IAM, or put API Gateway in front and authorize in "
                    "code. (Unauthenticated Function URLs are also blocked by policy in "
                    "the deployment account — they return 403 regardless.)"
                )
