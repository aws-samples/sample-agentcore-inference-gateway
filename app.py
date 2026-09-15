#!/usr/bin/env python3
"""CDK app entry point for the AgentCore Gateway inference-governance pilot."""
import aws_cdk as cdk

from pilot import config
from pilot.foundation_stack import FoundationStack

app = cdk.App()

env = cdk.Environment(account=config.AWS_ACCOUNT, region=config.AWS_REGION)

FoundationStack(
    app,
    config.STACK_NAME,
    env=env,
    description="AgentCore Gateway inference-governance pilot - foundation (isolated; acgw-pilot-*).",
)

app.synth()
