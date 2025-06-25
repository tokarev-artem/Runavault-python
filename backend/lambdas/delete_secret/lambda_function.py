import os
import boto3
from jwtlib import verify_token, format_response, parse_body, get_auth_token

dynamodb = boto3.client('dynamodb')
TABLE_PREFIX = os.environ.get("TABLE_PREFIX", "RunaVault_")

def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded = verify_token(token)
        user_id = decoded["sub"]

        body = parse_body(event.get("body"))
        if not body or "site" not in body:
            return format_response(400, {"message": "Missing site parameter"})

        site = body["site"]
        provided_user_id = body.get("user_id", user_id)
        subdirectory = body.get("subdirectory", "")

        if provided_user_id != user_id:
            return format_response(403, {"message": "You can only delete your own secrets"})

        query_response = dynamodb.query(
            TableName=f"{TABLE_PREFIX}passwords",
            KeyConditionExpression="user_id = :user_id AND begins_with(site, :site_prefix)",
            ExpressionAttributeValues={
                ":user_id": {"S": user_id},
                ":site_prefix": {"S": site}
            }
        )

        items = query_response.get("Items", [])
        if not items:
            return format_response(404, {"message": "Password not found"})

        matching_items = [
            item for item in items
            if item.get("subdirectory", {}).get("S", "") == subdirectory
        ]

        if not matching_items:
            return format_response(404, {"message": "Password not found"})

        for item in matching_items:
            print(f"Deleting item with site key: {item['site']['S']}")
            dynamodb.delete_item(
                TableName=f"{TABLE_PREFIX}passwords",
                Key={
                    "user_id": {"S": user_id},
                    "site": {"S": item["site"]["S"]}
                }
            )

        return format_response(200, {
            "message": "Password deleted successfully",
            "count": len(matching_items)
        })

    except Exception as e:
        print("Error deleting password:", e)
        message = str(e)
        status_code = 401 if "Unauthorized" in message else 404 if "not found" in message else 500
        return format_response(status_code, {"message": message or "Internal Server Error"})
