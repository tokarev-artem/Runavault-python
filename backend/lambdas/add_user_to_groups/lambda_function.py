import os
import boto3
import logging
from jwtlib import get_auth_token, verify_token, parse_body, format_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)

USER_POOL_ID = os.environ.get("USER_POOL_ID")
AWS_REGION = os.environ.get("AWS_REGION")

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded_token = verify_token(token)
        current_user = decoded_token.get("sub")

        user_groups = decoded_token.get("cognito:groups", [])
        if "Admin" not in user_groups:
            return format_response(403, {"message": "Forbidden: Only Admin users can perform this action"})

        body = parse_body(event.get("body", "{}"))
        username = body.get("username")
        groups = body.get("groups")

        if not username or not isinstance(groups, list) or len(groups) == 0:
            raise ValueError("Username and at least one group are required")

        for group_name in groups:
            cognito.admin_add_user_to_group(
                UserPoolId=USER_POOL_ID,
                Username=username,
                GroupName=group_name
            )

        requires_session_update = username in [
            current_user,
            decoded_token.get("email"),
            decoded_token.get("username")
        ]

        return format_response(200, {
            "message": "User added to groups successfully",
            "requiresSessionUpdate": requires_session_update
        })

    except Exception as e:
        logger.exception("Error while adding user to groups")
        status_code = 401 if "Unauthorized" in str(e) else 400
        return format_response(status_code, {"message": str(e)})
