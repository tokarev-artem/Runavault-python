import os
import boto3
from botocore.exceptions import ClientError
from jwtlib import verify_token, format_response, get_auth_token

USER_POOL_ID = os.environ["USER_POOL_ID"]
AWS_REGION = os.environ["AWS_REGION"]

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded = verify_token(token)
        user_id = decoded["sub"]

        params = {
            "UserPoolId": USER_POOL_ID,
            "AttributesToGet": ["email", "given_name", "family_name"],
            "Limit": 60
        }

        users = []
        pagination_token = None

        while True:
            if pagination_token:
                params["PaginationToken"] = pagination_token

            response = cognito.list_users(**params)
            for user in response.get("Users", []):
                attributes = {attr["Name"]: attr["Value"] for attr in user.get("Attributes", [])}
                email = attributes.get("email", "No email")
                given_name = attributes.get("given_name", "")
                family_name = attributes.get("family_name", "")

                users.append({
                    "username": user["Username"],
                    "email": email,
                    "given_name": given_name,
                    "family_name": family_name
                })

            pagination_token = response.get("PaginationToken")
            if not pagination_token:
                break

        # Format users with label/value
        formatted_users = []
        for user in users:
            email = user["email"]
            given_name = user.get("given_name", "")
            family_name = user.get("family_name", "")
            label = email

            if "@" in email:
                if given_name or family_name:
                    full_name = f"{given_name} {family_name}".strip()
                    label = f"{full_name} ({email})"

            formatted_users.append({
                "value": user["username"],
                "label": label,
                "email": email,
                "given_name": given_name,
                "family_name": family_name
            })

        # Sort logic
        def sort_key(user):
            name = f"{user.get('given_name', '')} {user.get('family_name', '')}".strip()
            return (name.lower() if name else user["email"].lower())

        formatted_users.sort(key=sort_key)

        return format_response(200, {"users": formatted_users})

    except Exception as error:
        status_code = 401 if "Unauthorized" in str(error) else 500
        return format_response(status_code, {
            "message": str(error) or "Internal Server Error"
        })
