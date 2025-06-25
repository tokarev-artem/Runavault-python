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
        logger.info("User admin operation started")

        token = get_auth_token(event)
        decoded_token = verify_token(token)
        user_groups = decoded_token.get("cognito:groups", [])

        if "Admin" not in user_groups:
            logger.warning("User is not in Admin group")
            return format_response(403, {"message": "Forbidden: Only Admin users can perform this action"})

        body = parse_body(event.get("body", "{}"))
        username = body.get("username")
        delete_user = body.get("deleteUser")
        edit_user = body.get("editUser")
        new_username = body.get("newUsername")
        given_name = body.get("given_name")
        family_name = body.get("family_name")
        password = body.get("password")

        if not username:
            return format_response(400, {"message": "Username is required"})

        # Delete user
        if delete_user:
            cognito.admin_delete_user(
                UserPoolId=USER_POOL_ID,
                Username=username
            )
            return format_response(200, {"message": "User deleted successfully"})

        # Edit user
        if edit_user:
            user_attributes = []

            if new_username:
                user_attributes.append({"Name": "email", "Value": new_username})
            if given_name:
                user_attributes.append({"Name": "given_name", "Value": given_name})
            if family_name:
                user_attributes.append({"Name": "family_name", "Value": family_name})

            if user_attributes:
                cognito.admin_update_user_attributes(
                    UserPoolId=USER_POOL_ID,
                    Username=username,
                    UserAttributes=user_attributes
                )

            if password:
                cognito.admin_reset_user_password(
                    UserPoolId=USER_POOL_ID,
                    Username=username
                )

            return format_response(200, {"message": "User updated successfully"})

        return format_response(400, {"message": "No valid action specified (delete or edit)"})

    except Exception as e:
        logger.exception("Error during user management")
        status_code = 401 if "Unauthorized" in str(e) else 500
        return format_response(status_code, {
            "message": str(e) or "Internal Server Error"
        })
