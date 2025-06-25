import os
import boto3
import logging
from jwtlib import verify_token, format_response, parse_body, get_auth_token

logger = logging.getLogger()
logger.setLevel(logging.INFO)

USER_POOL_ID = os.environ.get("USER_POOL_ID")
AWS_REGION = os.environ.get("AWS_REGION")

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

def lambda_handler(event, context):
    logger.info("Lambda triggered")
    logger.debug(f"Event received: {event}")

    try:
        token = get_auth_token(event)
        logger.info("Token extracted")

        verify_token(token)
        logger.info("Token verified")

        body = parse_body(event.get("body", "{}"))
        username = body.get("username")
        list_all_users = body.get("listAllUsers", False)

        if list_all_users:
            logger.info("Listing all users with groups")

            users = []
            next_token = None

            while True:
                params = {
                    "UserPoolId": USER_POOL_ID,
                    "Limit": 60
                }
                if next_token:
                    params["PaginationToken"] = next_token

                response = cognito.list_users(**params)
                logger.debug(f"List users response: {response}")

                batch_users = []
                for user in response.get("Users", []):
                    group_list = []
                    group_token = None
                    while True:
                        group_params = {
                            "UserPoolId": USER_POOL_ID,
                            "Username": user["Username"],
                            "Limit": 60
                        }
                        if group_token:
                            group_params["NextToken"] = group_token

                        group_response = cognito.admin_list_groups_for_user(**group_params)
                        logger.debug(f"Groups for {user['Username']}: {group_response}")

                        group_list.extend({
                            "value": g["GroupName"],
                            "label": g["GroupName"]
                        } for g in group_response.get("Groups", []))

                        group_token = group_response.get("NextToken")
                        if not group_token:
                            break

                    email = next((a["Value"] for a in user["Attributes"] if a["Name"] == "email"), None)

                    batch_users.append({
                        "username": user["Username"],
                        "email": email,
                        "enabled": user.get("Enabled"),
                        "status": user.get("UserStatus"),
                        "groups": group_list
                    })

                users.extend(batch_users)
                next_token = response.get("PaginationToken")
                if not next_token:
                    break

            return format_response(200, {"users": users})

        if not username:
            logger.warning("Username not provided and listAllUsers is false")
            return format_response(400, {"message": "Username is required when not listing all users"})

        logger.info(f"Listing groups for user: {username}")
        groups = []
        next_token = None

        while True:
            params = {
                "UserPoolId": USER_POOL_ID,
                "Username": username,
                "Limit": 60
            }
            if next_token:
                params["NextToken"] = next_token

            response = cognito.admin_list_groups_for_user(**params)
            logger.debug(f"Group response for {username}: {response}")

            groups.extend({
                "value": g["GroupName"],
                "label": g["GroupName"]
            } for g in response.get("Groups", []))

            next_token = response.get("NextToken")
            if not next_token:
                break

        return format_response(200, {"groups": groups})

    except Exception as e:
        logger.exception("Unhandled exception")
        status_code = 401 if "Unauthorized" in str(e) else 500
        return format_response(status_code, {
            "message": str(e) or "Internal Server Error"
        })
