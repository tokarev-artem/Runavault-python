import os
import json
import boto3
from jwtlib import verify_token, format_response, parse_body, get_auth_token
from datetime import datetime, timezone

dynamodb = boto3.client("dynamodb")
TABLE_PREFIX = os.environ.get("TABLE_PREFIX", "RunaVault_")
MAX_NOTES_LENGTH = 500

def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded = verify_token(token)
        user_id_from_token = decoded["sub"]
        body = parse_body(event.get("body", {}))

        if "site" not in body:
            return format_response(400, {"message": "Missing site parameter"})

        site = body["site"]
        user_id = body.get("user_id", user_id_from_token)
        subdirectory = body.get("subdirectory", "default")
        favorite = body.get("favorite")
        username = body.get("username")
        password = body.get("password")
        encrypted = body.get("encrypted", True)
        shared_with = body.get("sharedWith")
        notes = body.get("notes")
        tags = body.get("tags")

        if "#" not in site:
            return format_response(400, {
                "message": "Invalid site format: Must include password_id (e.g., 'baseSite#password_id')"
            })

        if notes and len(notes) > MAX_NOTES_LENGTH:
            return format_response(400, {
                "message": f"Notes cannot exceed {MAX_NOTES_LENGTH} characters"
            })

        user_groups = decoded.get("cognito:groups", [])

        query_response = dynamodb.query(
            TableName=f"{TABLE_PREFIX}passwords",
            KeyConditionExpression="user_id = :user_id AND begins_with(site, :site)",
            ExpressionAttributeValues={
                ":user_id": {"S": user_id},
                ":site": {"S": site}
            }
        )

        items = query_response.get("Items", [])
        if not items:
            return format_response(404, {"message": "Password not found"})

        existing_item = items[0]
        stored_subdirectory = existing_item.get("subdirectory", {}).get("S", "default")
        is_subdirectory_changed = subdirectory != stored_subdirectory
        is_owner = user_id == user_id_from_token
        has_edit_permission = is_owner

        if not is_owner:
            roles_map = existing_item.get("shared_with_roles", {}).get("M", {})
            for group in user_groups:
                if roles_map.get(group, {}).get("S") == "editor":
                    has_edit_permission = True
                    break

            if not has_edit_permission:
                return format_response(403, {
                    "message": "Permission denied: You can only edit your own secrets or those where you're an editor"
                })

        existing_shared_with = {
            "users": [item["shared_with_users"]["S"] for item in items if item.get("shared_with_users", {}).get("S") != "NONE"],
            "groups": [item["shared_with_groups"]["S"] for item in items if item.get("shared_with_groups", {}).get("S") != "NONE"],
            "roles": {k: v["S"] for k, v in existing_item.get("shared_with_roles", {}).get("M", {}).items()} if "shared_with_roles" in existing_item else {},
        }

        updated_shared_with = {
            "users": shared_with.get("users", existing_shared_with["users"]) if shared_with else existing_shared_with["users"],
            "groups": shared_with.get("groups", existing_shared_with["groups"]) if shared_with else existing_shared_with["groups"],
            "roles": shared_with.get("roles", existing_shared_with["roles"]) if shared_with else existing_shared_with["roles"],
        }

        last_modified = datetime.now(timezone.utc).isoformat()

        version = str(int(existing_item.get("version", {}).get("N", "0")) + 1)

        base_item = {
            "user_id": {"S": user_id},
            "username": {"S": username or existing_item["username"]["S"]},
            "password": {"S": password or existing_item["password"]["S"]},
            "encrypted": {"BOOL": encrypted if isinstance(encrypted, bool) else True},
            "shared_with_roles": {
                "M": {k: {"S": v} for k, v in updated_shared_with["roles"].items()}
            } if updated_shared_with["roles"] else existing_item.get("shared_with_roles", {"M": {}}),
            "subdirectory": {"S": subdirectory},
            "last_modified": {"S": last_modified},
            "notes": {"S": notes or existing_item.get("notes", {}).get("S", "")},
            "tags": {"SS": tags if tags else ["NONE"]},
            "favorite": {"BOOL": favorite if isinstance(favorite, bool) else existing_item.get("favorite", {}).get("BOOL", False)},
            "version": {"N": version},
            "password_id": {"S": existing_item.get("password_id", {}).get("S", site.split("#")[2] if len(site.split("#")) > 2 else "")}
        }

        # Delete existing items
        for item in items:
            dynamodb.delete_item(
                TableName=f"{TABLE_PREFIX}passwords",
                Key={
                    "user_id": {"S": user_id},
                    "site": {"S": item["site"]["S"]}
                }
            )

        # Write updated items
        put_items = []
        users = updated_shared_with["users"] or ["NONE"]
        groups = updated_shared_with["groups"] or ["NONE"]

        for group in groups:
            composite_site = f"{site}#group:{group}"
            item = {
                **base_item,
                "site": {"S": composite_site},
                "shared_with_groups": {"S": group},
                "shared_with_users": {"S": "NONE"}
            }
            put_items.append(item)

        for shared_user in users:
            composite_site = f"{site}#user:{shared_user}"
            item = {
                **base_item,
                "site": {"S": composite_site},
                "shared_with_groups": {"S": "NONE"},
                "shared_with_users": {"S": shared_user}
            }
            put_items.append(item)

        for item in put_items:
            try:
                dynamodb.put_item(
                    TableName=f"{TABLE_PREFIX}passwords",
                    Item=item,
                    ConditionExpression="attribute_not_exists(user_id) AND attribute_not_exists(site)"
                )
            except dynamodb.exceptions.ConditionalCheckFailedException:
                raise Exception(f"An item already exists for {item['site']['S']}")

        return format_response(200, {
            "message": "Password updated successfully and moved to new subdirectory" if is_subdirectory_changed else "Password updated successfully",
            "secret": {
                "site": site,
                "subdirectory": base_item["subdirectory"]["S"],
                "favorite": base_item["favorite"]["BOOL"],
                "username": base_item["username"]["S"],
                "password": base_item["password"]["S"],
                "encrypted": base_item["encrypted"]["BOOL"],
                "sharedWith": {
                    "users": [] if users[0] == "NONE" else users,
                    "groups": [] if groups[0] == "NONE" else groups,
                    "roles": updated_shared_with["roles"],
                },
                "notes": base_item["notes"]["S"],
                "tags": [tag for tag in base_item["tags"]["SS"] if tag != "NONE"],
                "last_modified": last_modified,
                "version": int(base_item["version"]["N"]),
                "password_id": base_item["password_id"]["S"]
            }
        })

    except Exception as e:
        print(f"Error updating secret: {e}")
        message = str(e)
        status_code = 401 if "Unauthorized" in message else 404 if "not found" in message else 500
        return format_response(status_code, {"message": message})
