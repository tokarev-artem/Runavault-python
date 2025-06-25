from aws_cdk import (
    Stack,
    aws_cognito as cognito,
    aws_dynamodb as dynamodb,
    aws_lambda as lambda_,
    aws_apigatewayv2 as apigw,
    aws_apigatewayv2_integrations as apigw_integrations,
    aws_kms as kms,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as cloudfront_origins,
    aws_iam as iam,
    aws_s3_deployment as s3_deployment,
    CfnOutput,
    Duration
)
from constructs import Construct

class RunaVaultStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.create_s3()
        self.create_kms()
        self.create_cognito()
        self.create_dynamodb()
        self.create_lambda_layer()
        self.create_lambda_functions()
        self.create_api_gateway()
        self.create_cloudfront()
        self.deploy_frontend()

    def create_s3(self):
        self.frontend_bucket = s3.Bucket(
            self, "RunaVaultFrontendBucket",
            bucket_name=f"runavault-{self.account}-{self.region}-{self.stack_name.lower()[-8:]}",
            website_index_document="index.html",
            website_error_document="index.html",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED
        )

    def create_cognito(self):
        # Create Cognito User Pool
        self.user_pool = cognito.UserPool(
            self, "RunaVaultUserPool",
            self_sign_up_enabled=False,
            auto_verify=cognito.AutoVerifiedAttrs(email=True),
            standard_attributes={
                "email": {"required": True, "mutable": True},
                "given_name": {"required": True, "mutable": True},
                "family_name": {"required": True, "mutable": True}
            },
            mfa=cognito.Mfa.REQUIRED,  
            mfa_second_factor=cognito.MfaSecondFactor(
                otp=True,  
                sms=False  
            ),
        )

        # Create Cognito Groups
        self.cognito_groups = {}
        for group_name in ["Admin", "Users", "Managers"]:
            self.cognito_groups[group_name] = cognito.CfnUserPoolGroup(
                self, f"RunaVault{group_name}Group",
                user_pool_id=self.user_pool.user_pool_id,
                group_name=group_name
            )

        # Create User Pool Client
        self.user_pool_client = cognito.UserPoolClient(
            self, "RunaVaultUserPoolClient",
            user_pool=self.user_pool,
            auth_flows={
                "admin_user_password": True,
                "user_password": True,
                "user_srp": True
            },
            generate_secret=False
        )

        # Add Cognito Domain
        self.user_pool_domain = cognito.UserPoolDomain(
            self, "RunaVaultUserPoolDomain",
            user_pool=self.user_pool,
            cognito_domain=cognito.CognitoDomainOptions(
                domain_prefix=f"runavault-{self.account}"
            )
        )

        # Add Identity Pool
        self.identity_pool = cognito.CfnIdentityPool(
            self, "RunaVaultIdentityPool",
            identity_pool_name="RunaVaultIdentityPool",
            allow_unauthenticated_identities=False,
            cognito_identity_providers=[
                cognito.CfnIdentityPool.CognitoIdentityProviderProperty(
                    client_id=self.user_pool_client.user_pool_client_id,
                    provider_name=f"cognito-idp.{self.region}.amazonaws.com/{self.user_pool.user_pool_id}",
                    server_side_token_check=False
                )
            ]
        )
        
        # Add Authenticated Role
        self.authenticated_role = iam.Role(
            self, "CognitoAuthenticatedRole",
            assumed_by=iam.FederatedPrincipal(
                "cognito-identity.amazonaws.com",
                conditions={
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": self.identity_pool.ref},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"}
                },
                assume_role_action="sts:AssumeRoleWithWebIdentity"
            )
        )
        
        # Add KMS permissions
        self.kms_key.grant_encrypt_decrypt(self.authenticated_role)
        
        # Attach role to Identity Pool
        cognito.CfnIdentityPoolRoleAttachment(
            self, "IdentityPoolRoleAttachment",
            identity_pool_id=self.identity_pool.ref,
            roles={"authenticated": self.authenticated_role.role_arn}
        )

        # Outputs
        CfnOutput(self, "COGNITO_ID", value=self.user_pool.user_pool_id)
        CfnOutput(self, "COGNITO_CLIENT_ID", value=self.user_pool_client.user_pool_client_id)
        CfnOutput(self, "COGNITO_DOMAIN", 
            value=f"https://{self.user_pool_domain.domain_name}.auth.{self.region}.amazoncognito.com")
        CfnOutput(self, "IDENTITY_POOL_ID", value=self.identity_pool.ref)
        CfnOutput(self, "KMS_KEY_ID", value=self.kms_key.key_arn)

    def create_dynamodb(self):
        self.passwords_table = dynamodb.Table(
            self, "RunaVaultPasswords",
            table_name="RunaVault_passwords",
            partition_key=dynamodb.Attribute(
                name="user_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="site",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            )
        )

        # Add Global Secondary Indexes
        self.passwords_table.add_global_secondary_index(
            index_name="shared_with_groups-index",
            partition_key=dynamodb.Attribute(
                name="shared_with_groups",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        self.passwords_table.add_global_secondary_index(
            index_name="shared_with_users-index",
            partition_key=dynamodb.Attribute(
                name="shared_with_users",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Output table name
        # CfnOutput(self, "PasswordsTableName", value=self.passwords_table.table_name)

    def create_kms(self):
        # Create KMS key for encryption
        self.kms_key = kms.Key(
            self, "RunaVaultKMSKey",
            enable_key_rotation=True,
            description="KMS key for RunaVault encryption"
        )

    def create_lambda_layer(self):
        self.pyjwt_layer = lambda_.LayerVersion(
            self, "PyJWTLayer",
            code=lambda_.Code.from_asset(
                "../backend/lambdas/layers/pyjwt",
                bundling={
                    "image": lambda_.Runtime.PYTHON_3_9.bundling_image,
                    "platform": "linux/arm64",
                    "command": [
                        "bash", "-c",
                        "pip install -r requirements.txt -t /asset-output/python && "
                        "cp -r python /asset-output/ && "
                        "find /asset-output -name '*.dist-info' -exec rm -rf {} + && "
                        "find /asset-output -name '__pycache__' -exec rm -rf {} +"
                    ]
                }
            ),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            compatible_architectures=[lambda_.Architecture.ARM_64],
            description="Layer containing PyJWT for token verification"
        )

    def create_lambda_functions(self):
        common_lambda_config = {
            "runtime": lambda_.Runtime.PYTHON_3_12,
            "environment": {
                "USER_POOL_ID": self.user_pool.user_pool_id,
                "CLIENT_ID": self.user_pool_client.user_pool_client_id
            },
            "layers": [self.pyjwt_layer],
            "timeout": Duration.seconds(30),
            "architecture": lambda_.Architecture.ARM_64
        }

        self.lambda_functions = {}

        secret_lambdas = [
            "create_secret", "delete_secret", "edit_secret",
            "get_secret", "list_secrets", "share_directory"
        ]

        for lambda_name in secret_lambdas:
            if lambda_name == "list_secrets":
                list_secrets_fn = lambda_.Function(
                    self, "RunaVaultListsecretsLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/list_secrets"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                
                list_secrets_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["dynamodb:Query", "dynamodb:GetItem"],
                        resources=[
                            self.passwords_table.table_arn,
                            f"{self.passwords_table.table_arn}/index/shared_with_groups-index",
                            f"{self.passwords_table.table_arn}/index/shared_with_users-index"
                        ]
                    )
                )
                
                self.lambda_functions[lambda_name] = list_secrets_fn
            elif lambda_name == "create_secret":
                create_secret_fn = lambda_.Function(
                    self, "RunaVaultCreatesecretLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/create_secret"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                create_secret_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["dynamodb:PutItem", "dynamodb:GetItem"],
                        resources=[self.passwords_table.table_arn]
                    )
                )
                self.lambda_functions[lambda_name] = create_secret_fn
            else:
                self.lambda_functions[lambda_name] = lambda_.Function(
                    self, f"RunaVault{lambda_name.capitalize().replace('_', '')}Lambda",
                    code=lambda_.Code.from_asset(
                        f"../backend/lambdas/{lambda_name}"
                    ),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                self.passwords_table.grant_read_write_data(self.lambda_functions[lambda_name])

        user_lambdas = [
            "list_users", "create_user", "edit_users",
            "add_user_to_groups", "remove_user_from_groups", "list_user_groups",
            "list_groups", "create_group", "delete_group"
        ]

        for lambda_name in user_lambdas:
            if lambda_name == "list_users":
                list_users_fn = lambda_.Function(
                    self, "RunaVaultListusersLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/list_users"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                list_users_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:ListUsers"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = list_users_fn
            elif lambda_name == "list_groups":
                list_groups_fn = lambda_.Function(
                    self, "RunaVaultListgroupsLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/list_groups"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                list_groups_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:ListGroups"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = list_groups_fn
            elif lambda_name == "list_user_groups":
                list_user_groups_fn = lambda_.Function(
                    self, "RunaVaultListusergroupsLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/list_user_groups"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                list_user_groups_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:ListUsers", "cognito-idp:AdminListGroupsForUser"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = list_user_groups_fn
            elif lambda_name == "create_user":
                create_user_fn = lambda_.Function(
                    self, "RunaVaultCreateuserLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/create_user"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                create_user_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:AdminCreateUser", "cognito-idp:AdminAddUserToGroup"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = create_user_fn
            elif lambda_name == "create_group":
                create_group_fn = lambda_.Function(
                    self, "RunaVaultCreategroupLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/create_group"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                create_group_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:CreateGroup"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = create_group_fn
            elif lambda_name == "edit_users":
                edit_users_fn = lambda_.Function(
                    self, "RunaVaultEditusersLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/edit_users"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                edit_users_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=[
                            "cognito-idp:AdminUpdateUserAttributes",
                            "cognito-idp:AdminResetUserPassword",
                            "cognito-idp:AdminDeleteUser"
                        ],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = edit_users_fn
            elif lambda_name == "delete_group":
                delete_group_fn = lambda_.Function(
                    self, "RunaVaultDeletegroupLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/delete_group"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                delete_group_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:DeleteGroup"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = delete_group_fn
            elif lambda_name == "add_user_to_groups":
                add_user_to_groups_fn = lambda_.Function(
                    self, "RunaVaultAddusertogroupsLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/add_user_to_groups"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                add_user_to_groups_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:AdminAddUserToGroup"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = add_user_to_groups_fn
            elif lambda_name == "remove_user_from_groups":
                remove_user_from_groups_fn = lambda_.Function(
                    self, "RunaVaultRemoveuserfromgroupsLambda",
                    code=lambda_.Code.from_asset("../backend/lambdas/remove_user_from_groups"),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                remove_user_from_groups_fn.add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:AdminRemoveUserFromGroup"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )
                self.lambda_functions[lambda_name] = remove_user_from_groups_fn
            else:
                self.lambda_functions[lambda_name] = lambda_.Function(
                    self, f"RunaVault{lambda_name.capitalize().replace('_', '')}Lambda",
                    code=lambda_.Code.from_asset(
                        f"../backend/lambdas/{lambda_name}"
                    ),
                    handler="lambda_function.lambda_handler",
                    **common_lambda_config
                )
                self.passwords_table.grant_read_write_data(self.lambda_functions[lambda_name])
            
            # Add Cognito permissions for list_users
            if lambda_name == "list_users":
                self.lambda_functions[lambda_name].add_to_role_policy(
                    iam.PolicyStatement(
                        actions=["cognito-idp:ListUsers"],
                        resources=[self.user_pool.user_pool_arn]
                    )
                )

        # for lambda_name, fn in self.lambda_functions.items():
        #     CfnOutput(self, f"{lambda_name.capitalize()}LambdaArn", value=fn.function_arn)

    def create_api_gateway(self):
        from aws_cdk import aws_apigatewayv2 as apigwv2
        from aws_cdk import aws_lambda as lambda_
        from aws_cdk import aws_iam as iam

        # 1. Create HTTP API (L1) with placeholder CORS origin
        self.http_api = apigwv2.CfnApi(
            self, "RunaVaultHttpApi",
            name="RunaVault-api",
            protocol_type="HTTP",
            cors_configuration={
                "allowOrigins": ["*"],
                "allowMethods": ["OPTIONS", "GET", "POST"],
                "allowHeaders": ["Content-Type", "Authorization"]
            }
        )
        default_stage = apigwv2.CfnStage(
            self, "DefaultStage",
            api_id=self.http_api.ref,
            stage_name="$default",
            auto_deploy=True
        )
        # Create JWT Authorizer
        authorizer = apigwv2.CfnAuthorizer(
            self, "CognitoAuthorizer",
            api_id=self.http_api.ref,
            authorizer_type="JWT",
            identity_source=["$request.header.Authorization"],
            name="CognitoJwtAuthorizer",
            jwt_configuration={
                "audience": [self.user_pool_client.user_pool_client_id],
                "issuer": f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool.user_pool_id}"
            }
        )

        # Create Lambda Integrations
        integration_map = {}
        for name, fn in self.lambda_functions.items():
            integration_map[name] = apigwv2.CfnIntegration(
                self, f"{name.capitalize()}Integration",
                api_id=self.http_api.ref,
                integration_type="AWS_PROXY",
                integration_uri=fn.function_arn,
                integration_method="POST",
                payload_format_version="2.0"
            )
            fn.add_permission(
                f"ApiInvoke{name}",
                principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
                action="lambda:InvokeFunction",
                source_arn=f"arn:aws:execute-api:{self.region}:{self.account}:{self.http_api.ref}/*/*"
            )

        # Define all API routes
        route_definitions = []
        
        # Helper function to add route with OPTIONS
        def add_route_with_options(method, path, lambda_name=None):
            # Add main route
            if lambda_name:
                route_definitions.append({
                    "route_key": f"{method} {path}",
                    "lambda": lambda_name,
                    "auth": "JWT"
                })
            # Add OPTIONS route
            route_definitions.append({
                "route_key": f"OPTIONS {path}",
                "lambda": None,
                "auth": "NONE"
            })

        # Add all your routes
        add_route_with_options("GET", "/list_secrets", "list_secrets")
        add_route_with_options("POST", "/create_secret", "create_secret")
        add_route_with_options("GET", "/get_secret", "get_secret")
        add_route_with_options("POST", "/edit_secret", "edit_secret")
        add_route_with_options("POST", "/delete_secret", "delete_secret")
        add_route_with_options("GET", "/list_users", "list_users")
        add_route_with_options("POST", "/create_user", "create_user")
        add_route_with_options("POST", "/edit_users", "edit_users")
        add_route_with_options("POST", "/add_user_to_groups", "add_user_to_groups")
        add_route_with_options("POST", "/remove_user_from_groups", "remove_user_from_groups")
        add_route_with_options("POST", "/list_user_groups", "list_user_groups")
        add_route_with_options("POST", "/create_group", "create_group")
        add_route_with_options("GET", "/list_groups", "list_groups")
        add_route_with_options("POST", "/delete_group", "delete_group")
        add_route_with_options("POST", "/share_directory", "share_directory")

        # Create all routes
        for rd in route_definitions:
            route_args = {
                "scope": self,
                "id": f"{rd['route_key'].replace(' ', '_').replace('/', '_')}Route",
                "api_id": self.http_api.ref,
                "route_key": rd["route_key"],
                "authorization_type": rd["auth"],
            }

            if rd["lambda"]:
                route_args["target"] = f"integrations/{integration_map[rd['lambda']].ref}"
                if rd["auth"] == "JWT":
                    route_args["authorizer_id"] = authorizer.ref

            apigwv2.CfnRoute(**route_args)

        # Output API endpoint
        # CfnOutput(
        #     self, "API_GATEWAY_ENDPOINT",
        #     value=f"https://{self.http_api.ref}.execute-api.{self.region}.amazonaws.com"
        # )
        CfnOutput(
            self, "API_GATEWAY_ENDPOINT",
            value=f"https://{self.http_api.ref}.execute-api.{self.region}.amazonaws.com",
            export_name="API-GATEWAY-ENDPOINT"  # This preserves underscores in the exported name
        )
    def create_cloudfront(self):
        # Create OAC
        oac = cloudfront.CfnOriginAccessControl(
            self, "RunaVaultOAC",
            origin_access_control_config=cloudfront.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name="RunaVaultOAC",
                description="OAC for RunaVault frontend",
                signing_protocol="sigv4",
                signing_behavior="always",
                origin_access_control_origin_type="s3"
            )
        )

        # Create CloudFront Distribution
        self.cloudfront_distribution = cloudfront.Distribution(
            self, "RunaVaultDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront_origins.S3BucketOrigin(
                    bucket=self.frontend_bucket,
                    origin_access_control_id=oac.ref
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
            ),
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html"
                ),
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html"
                )
            ]
        )

        # Add S3 bucket policy for CloudFront OAC
        self.frontend_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[self.frontend_bucket.arn_for_objects("*")],
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": self.cloudfront_distribution.distribution_arn
                    }
                }
            )
        )
        # Output CloudFront domain
        CfnOutput(self, "CloudFrontURL", value=f"https://{self.cloudfront_distribution.domain_name}")

    def deploy_frontend(self):
        # Deploy frontend assets to S3
        s3_deployment.BucketDeployment(
            self, "FrontendDeployment",
            sources=[s3_deployment.Source.asset("../frontend/build")],
            destination_bucket=self.frontend_bucket
        )

        # Output deployment instructions
        CfnOutput(
            self, "FrontendBuildInstructions",
            value="Run 'npm install && npm run build' in /frontend before deploying"
        )