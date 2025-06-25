import os
import json
import boto3
from datetime import datetime
from botocore.exceptions import ClientError
from jwtlib import get_auth_token, verify_token, parse_body, format_response

dynamodb = boto3.client("dynamodb")
TABLE_PREFIX = os.environ.get("TABLE_PREFIX", "RunaVault_")


def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded = verify_token(token)
        user_id = decoded["sub"]

        body = parse_body(event.get("body", "{}"))
        subdirectory = body.get("subdirectory")
        shared_with = body.get("sharedWith")

        if not subdirectory:
            return format_response(400, {"message": "Missing subdirectory"})
        effective_sub = "" if subdirectory == "default" else subdirectory

        if not isinstance(shared_with, dict):
            return format_response(400, {"message": "'sharedWith' must be an object"})
        users = shared_with.get("users") or []
        groups = shared_with.get("groups") or []
        roles = shared_with.get("roles") or {}

        if not (isinstance(users, list) and isinstance(groups, list)):
            return format_response(400, {"message": "users/groups must be arrays"})
        if not users and not groups:
            return format_response(400, {"message": "At least one user or group required"})

        print(f"Sharing with {len(users)} users and {len(groups)} groups.")

        resp = dynamodb.query(
            TableName=f"{TABLE_PREFIX}passwords",
            KeyConditionExpression="user_id = :u",
            ExpressionAttributeValues={":u": {"S": user_id}}
        )
        items = resp.get("Items", [])
        filtered = [i for i in items if i.get("subdirectory", {}).get("S", "default") == effective_sub]
        if not filtered:
            return format_response(404, {"message": "No secrets in that subdirectory"})

        updated = []
        now = datetime.utcnow().isoformat()

        # group by password_id
        grouped = {}
        for it in filtered:
            site = it["site"]["S"]
            parts = site.split("#")
            pwd = it.get("password_id", {}).get("S") or (parts[-2] if len(parts) >= 3 else site)
            grouped.setdefault(pwd, []).append(it)

        for pwd, group_items in grouped.items():
            base = group_items[0]
            parts = base["site"]["S"].split("#")
            base_key = "#".join(parts[:-1]) if len(parts) >= 3 else f"{parts[0]}#{pwd}"

            existing_users = {i["shared_with_users"]["S"]
                              for i in group_items if i.get("shared_with_users", {}).get("S") != "NONE"}
            existing_groups = {i["shared_with_groups"]["S"]
                               for i in group_items if i.get("shared_with_groups", {}).get("S") != "NONE"}

            new_users = list(existing_users.union(users))
            new_groups = list(existing_groups.union(groups))
            existing_sites = {i["site"]["S"] for i in group_items}

            # delete old
            for it in group_items:
                try:
                    dynamodb.delete_item(
                        TableName=f"{TABLE_PREFIX}passwords",
                        Key={"user_id": {"S": user_id}, "site": {"S": it["site"]["S"]}}
                    )
                except ClientError as e:
                    print("Ignore delete error:", e)

            # prepare base item
            roles_map = {
                **base.get("shared_with_roles", {}).get("M", {}),
                **{k: {"S": v} for k, v in roles.items()}
            }
            base_item = {
                "user_id": {"S": user_id},
                "username": base["username"],
                "password": base["password"],
                "encrypted": base.get("encrypted", {"BOOL": True}),
                "shared_with_roles": {"M": roles_map},
                "subdirectory": base.get("subdirectory", {"S": "default"}),
                "last_modified": {"S": now},
                "notes": base.get("notes", {"S": ""}),
                "tags": base.get("tags", {"SS": ["NONE"]}),
                "favorite": base.get("favorite", {"BOOL": False}),
                "version": {"N": str(int(base.get("version", {"N": "1"})["N"]) + 1)},
                "password_id": {"S": pwd},
            }

            def store(composite_key, grp, usr):
                itm = {
                    **base_item,
                    "site": {"S": composite_key},
                    "shared_with_groups": {"S": grp},
                    "shared_with_users": {"S": usr},
                }
                try:
                    if composite_key in existing_sites:
                        dynamodb.put_item(TableName=f"{TABLE_PREFIX}passwords", Item=itm)
                    else:
                        dynamodb.put_item(TableName=f"{TABLE_PREFIX}passwords",
                                          Item=itm,
                                          ConditionExpression="attribute_not_exists(user_id) AND attribute_not_exists(site)")
                except ClientError as e:
                    if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                        print("Error writing item:", e)
                        raise

            for g in new_groups:
                if g == "NONE" and len(new_groups) > 1: continue
                store(f"{base_key}#group:{g}", g, "NONE")
            for u in new_users:
                if u == "NONE" and len(new_users) > 1: continue
                store(f"{base_key}#user:{u}", "NONE", u)

            updated.append({
                "site": parts[0],
                "subdirectory": base_item["subdirectory"]["S"],
                "favorite": base_item["favorite"]["BOOL"],
                "username": base_item["username"]["S"],
                "password": base_item["password"]["S"],
                "encrypted": base_item["encrypted"]["BOOL"],
                "sharedWith": {
                    "users": [] if not new_users else new_users,
                    "groups": [] if not new_groups else new_groups,
                    "roles": roles
                },
                "notes": base_item["notes"]["S"],
                "tags": [t for t in base_item["tags"]["SS"] if t != "NONE"],
                "last_modified": now,
                "version": int(base_item["version"]["N"])
            })

        return format_response(200, {"message": "Directory shared", "secrets": updated})

    except Exception as ex:
        print("Error:", str(ex))
        code = 401 if "Unauthorized" in str(ex) else 404 if "not found" in str(ex).lower() else 500
        return format_response(code, {"message": str(ex)})
