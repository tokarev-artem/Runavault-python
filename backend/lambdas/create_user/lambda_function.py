import os
import boto3
import logging
from jwtlib import verify_token, get_auth_token, parse_body, format_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)

USER_POOL_ID = os.environ.get("USER_POOL_ID")
AWS_REGION = os.environ.get("AWS_REGION")

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

def lambda_handler(event, context):
    try:
        logger.info("Received event")
        token = get_auth_token(event)
        decoded_token = verify_token(token)
        logger.info("Token verified")

        user_groups = decoded_token.get("cognito:groups", [])
        logger.debug(f"User groups: {user_groups}")

        if "Admin" not in user_groups:
            logger.warning("User is not in Admin group")
            return format_response(403, {
                "message": "Forbidden: Only Admin users can perform this action"
            })

        parsed_body = parse_body(event.get("body", "{}"))
        email = parsed_body.get("email")
        given_name = parsed_body.get("given_name")
        family_name = parsed_body.get("family_name")

        if not email:
            logger.warning("Email missing in request")
            return format_response(400, {
                "message": "Invalid request: email is required"
            })

        user_attributes = [
            {"Name": "email", "Value": email},
            {"Name": "email_verified", "Value": "true"}
        ]

        if given_name:
            user_attributes.append({"Name": "given_name", "Value": given_name})
        if family_name:
            user_attributes.append({"Name": "family_name", "Value": family_name})

        logger.info(f"Creating user {email} with attributes {user_attributes}")

        response = cognito.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=email,
            UserAttributes=user_attributes
        )

        logger.debug(f"Cognito response: {response}")
        return format_response(200, {
            "message": f"{email} user created successfully"
        })

    except Exception as e:
        logger.exception("Failed to create user")
        status_code = 401 if "Unauthorized" in str(e) else 400
        return format_response(status_code, {
            "message": str(e)
        })
