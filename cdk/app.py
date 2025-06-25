#!/usr/bin/env python3
from aws_cdk import App
from runa_vault_stack import RunaVaultStack

app = App()
RunaVaultStack(app, "RunaVaultStack")

app.synth()
