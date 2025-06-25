import os
import boto3
import logging
from jwtlib import get_auth_token, verify_token, parse_body, format_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)

USER_POOL_ID = os.environ.get("USER_POOL_ID")
cognito_client = boto3.client("cognito-idp")

def lambda_handler(event, context):
    try:
        logger.info("Received event for group creation")

        token = get_auth_token(event)
        decoded_token = verify_token(token)
        logger.info("Token verified")

        user_groups = decoded_token.get("cognito:groups", [])
        if "Admin" not in user_groups:
            logger.warning("Forbidden: User not in Admin group")
            return format_response(403, {
                "message": "Forbidden: Only Admin users can perform this action"
            })

        body = parse_body(event.get("body", "{}"))
        group_name = body.get("groupName")
        description = body.get("description")
        precedence = body.get("precedence")
        role_arn = body.get("roleArn")

        if not group_name:
            logger.warning("Missing groupName parameter")
            return format_response(400, {
                "message": "Missing groupName parameter"
            })

        logger.info(f"Creating group '{group_name}' in UserPool '{USER_POOL_ID}'")

        params = {
            "GroupName": group_name,
            "UserPoolId": USER_POOL_ID,
        }
        if description:
            params["Description"] = description
        if precedence is not None:
            params["Precedence"] = precedence
        if role_arn:
            params["RoleArn"] = role_arn

        response = cognito_client.create_group(**params)
        logger.debug(f"Cognito create_group response: {response}")

        return format_response(200, {
            "message": "Group created successfully"
        })

    except Exception as e:
        logger.exception("Failed to create group")
        status_code = 401 if "Unauthorized" in str(e) else 500
        return format_response(status_code, {
            "message": str(e) or "Internal Server Error"
        })
