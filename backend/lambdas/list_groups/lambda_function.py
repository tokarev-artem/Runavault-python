import os
import boto3
import logging
from jwtlib import verify_token, format_response, get_auth_token

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

USER_POOL_ID = os.environ.get("USER_POOL_ID")
AWS_REGION = os.environ.get("AWS_REGION")

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

def lambda_handler(event, context):
    logger.info("Lambda invoked")
    logger.debug(f"Event received: {event}")

    try:
        token = get_auth_token(event)
        logger.info("Token extracted from event")

        verify_token(token)
        logger.info("Token verified successfully")

        params = {
            "UserPoolId": USER_POOL_ID,
            "Limit": 60
        }

        groups = []
        next_token = None

        while True:
            if next_token:
                params["NextToken"] = next_token

            logger.info(f"Calling Cognito list_groups with params: {params}")
            response = cognito.list_groups(**params)
            logger.debug(f"Raw Cognito response: {response}")

            fetched_groups = response.get("Groups", [])
            logger.info(f"Fetched {len(fetched_groups)} groups")
            groups.extend({"GroupName": group["GroupName"]} for group in fetched_groups)

            next_token = response.get("NextToken")
            if not next_token:
                break

        groups.sort(key=lambda g: g["GroupName"])
        logger.info(f"Sorted groups: {[g['GroupName'] for g in groups]}")

        result = {
            "groups": [{"value": g["GroupName"], "label": g["GroupName"]} for g in groups]
        }
        return format_response(200, result)

    except Exception as e:
        logger.exception("Unhandled exception occurred")  # Logs traceback
        status_code = 401 if "Unauthorized" in str(e) else 500
        return format_response(status_code, {
            "message": str(e) or "Internal Server Error"
        })
