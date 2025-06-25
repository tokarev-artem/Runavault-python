import os
import json
import uuid
import boto3
from botocore.exceptions import ClientError
from jwtlib import verify_token, format_response, parse_body, get_auth_token
from datetime import datetime, timezone

dynamodb = boto3.client('dynamodb')
TABLE_PREFIX = os.getenv('TABLE_PREFIX', 'RunaVault_')
MAX_NOTES_LENGTH = 500

def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded = verify_token(token)
        user_id = decoded['sub']

        body = parse_body(event.get('body', '{}'))
        site = body.get('site')
        username = body.get('username')
        raw_password = body.get('password')
        encrypted = body.get('encrypted', True)
        shared_with = body.get('sharedWith', {'users': [], 'groups': [], 'roles': {}})
        subdirectory = body.get('subdirectory', '')
        notes = body.get('notes', '')
        tags = body.get('tags', [])
        favorite = body.get('favorite', False)
        version = body.get('version', 1)

        if not site or not username or not raw_password:
            return format_response(400, {
                "message": "Missing required parameters: site, username, and password are required"
            })

        if notes and len(notes) > MAX_NOTES_LENGTH:
            return format_response(400, {
                "message": f"Notes cannot exceed {MAX_NOTES_LENGTH} characters"
            })

        try:
            if isinstance(raw_password, str) and raw_password.startswith("{"):
                password_data = json.loads(raw_password)
            elif isinstance(raw_password, dict):
                password_data = raw_password
            else:
                password_data = {
                    "encryptedPassword": raw_password,
                    "sharedWith": {"users": [], "groups": []}
                }
        except Exception as e:
            print("Failed to parse password:", e)
            return format_response(400, {"message": "Invalid password format"})

        password_str = json.dumps(password_data) if isinstance(password_data, dict) else password_data
        last_modified = datetime.now(timezone.utc).isoformat()
        password_id = str(uuid.uuid4())

        sort_key_prefix = f"{site}#{subdirectory}" if subdirectory else site
        base_composite_key = f"{sort_key_prefix}#{password_id}"

        base_item = {
            'user_id': {'S': user_id},
            'username': {'S': username},
            'password': {'S': password_str},
            'encrypted': {'BOOL': encrypted},
            'shared_with_roles': {
                'M': {k: {'S': v} for k, v in shared_with.get('roles', {}).items()}
            },
            'subdirectory': {'S': subdirectory or "default"},
            'last_modified': {'S': last_modified},
            'notes': {'S': notes},
            'tags': {'SS': tags if tags else ["NONE"]},
            'favorite': {'BOOL': favorite},
            'version': {'N': str(version)},
            'password_id': {'S': password_id}
        }

        groups = shared_with.get('groups', []) or ["NONE"]
        users = shared_with.get('users', []) or ["NONE"]
        put_promises = []

        for group in groups:
            composite_key = f"{base_composite_key}#group:{group}"
            item = {
                **base_item,
                'site': {'S': composite_key},
                'shared_with_groups': {'S': group},
                'shared_with_users': {'S': "NONE"},
            }
            try:
                dynamodb.put_item(
                    TableName=f"{TABLE_PREFIX}passwords",
                    Item=item,
                    ConditionExpression="attribute_not_exists(user_id) AND attribute_not_exists(site)"
                )
            except ClientError as e:
                if e.response['Error']['Code'] == "ConditionalCheckFailedException":
                    raise Exception(f"An item with user_id {user_id} and site {composite_key} already exists for group {group}")
                else:
                    raise

        for shared_user in users:
            composite_key = f"{base_composite_key}#user:{shared_user}"
            item = {
                **base_item,
                'site': {'S': composite_key},
                'shared_with_groups': {'S': "NONE"},
                'shared_with_users': {'S': shared_user},
            }
            try:
                dynamodb.put_item(
                    TableName=f"{TABLE_PREFIX}passwords",
                    Item=item,
                    ConditionExpression="attribute_not_exists(user_id) AND attribute_not_exists(site)"
                )
            except ClientError as e:
                if e.response['Error']['Code'] == "ConditionalCheckFailedException":
                    raise Exception(f"An item with user_id {user_id} and site {composite_key} already exists for user {shared_user}")
                else:
                    raise

        # Retrieve one of the inserted items for confirmation
        first_key = (
            f"{base_composite_key}#group:{groups[0]}" if groups[0] != "NONE"
            else f"{base_composite_key}#user:{users[0]}"
        )

        response = dynamodb.get_item(
            TableName=f"{TABLE_PREFIX}passwords",
            Key={'user_id': {'S': user_id}, 'site': {'S': first_key}}
        )

        item = response.get('Item')
        if not item:
            return format_response(404, {"message": "Password not found after creation"})

        return format_response(200, {
            "site": item["site"]["S"],
            "username": item["username"]["S"],
            "password": item["password"]["S"],
            "encrypted": item["encrypted"]["BOOL"],
            "sharedWith": {
                "users": [] if users[0] == "NONE" else users,
                "groups": [] if groups[0] == "NONE" else groups,
                "roles": {k: v['S'] for k, v in item.get("shared_with_roles", {}).get("M", {}).items()}
            },
            "subdirectory": item["subdirectory"]["S"],
            "notes": item["notes"]["S"],
            "tags": [] if item["tags"]["SS"][0] == "NONE" else item["tags"]["SS"],
            "favorite": item["favorite"]["BOOL"],
            "version": int(item["version"]["N"]),
            "last_modified": item["last_modified"]["S"],
            "password_id": item["password_id"]["S"],
        })

    except Exception as e:
        print("Error:", e)
        message = str(e)
        status_code = (
            401 if "Unauthorized" in message else
            404 if "not found" in message else
            400 if "already exists" in message else
            500
        )
        return format_response(status_code, {"message": message or "Internal Server Error"})
