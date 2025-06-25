import os
import boto3
import logging
from jwtlib import get_auth_token, verify_token, parse_body, format_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)

USER_POOL_ID = os.environ.get("USER_POOL_ID")
cognito = boto3.client("cognito-idp")

def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded_token = verify_token(token)

        user_groups = decoded_token.get("cognito:groups", [])
        if "Admin" not in user_groups:
            return format_response(403, {"message": "Forbidden: Only Admin users can perform this action"})

        body = parse_body(event.get("body", "{}"))
        group_name = body.get("groupName")

        if not group_name:
            return format_response(400, {"message": "Missing groupName parameter"})

        if group_name.lower() == "admin":
            return format_response(400, {"message": "Cannot delete the Admin group"})

        cognito.delete_group(
            GroupName=group_name,
            UserPoolId=USER_POOL_ID
        )

        return format_response(200, {"message": "Group deleted successfully"})

    except cognito.exceptions.ResourceNotFoundException:
        return format_response(404, {"message": "Group not found"})

    except Exception as e:
        logger.exception("Error while deleting group")
        status_code = 401 if "Unauthorized" in str(e) else 500
        return format_response(status_code, {"message": str(e)})
