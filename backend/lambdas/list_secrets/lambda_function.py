import json
import os
import boto3
from botocore.exceptions import ClientError
from jwtlib import verify_token, format_response, get_auth_token

dynamodb = boto3.client('dynamodb')
TABLE_PREFIX = os.environ.get('TABLE_PREFIX', 'RunaVault_')

def get_auth_token(event):
    headers = event.get('headers', {})
    auth_header = headers.get('Authorization') or headers.get('authorization')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header[7:]
    raise Exception("Unauthorized: No token provided")


def format_response(status_code, body):
    return {
        'statusCode': status_code,
        'body': json.dumps(body),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }

def format_secret(item):
    try:
        password_data = json.loads(item['password']['S'])
    except Exception as e:
        print(f"Failed to parse password: {e}")
        password_data = {'encryptedPassword': item['password']['S'], 'sharedWith': {'users': [], 'groups': []}}

    site = item['site']['S']
    base_site = site.split('#group:')[0].split('#user:')[0]

    return {
        'user_id': item['user_id']['S'],
        'site': base_site,
        'password_id': item.get('password_id', {}).get('S', base_site.split('#')[2] if len(base_site.split('#')) > 2 else ''),
        'subdirectory': item.get('subdirectory', {}).get('S', 'default'),
        'username': item['username']['S'],
        'password': password_data,
        'encrypted': item.get('encrypted', {}).get('BOOL', True),
        'shared_with': {
            'users': [item['shared_with_users']['S']] if item.get('shared_with_users', {}).get('S') and item['shared_with_users']['S'] != 'NONE' else [],
            'groups': [item['shared_with_groups']['S']] if item.get('shared_with_groups', {}).get('S') and item['shared_with_groups']['S'] != 'NONE' else [],
            'roles': {k: v['S'] for k, v in item.get('shared_with_roles', {}).get('M', {}).items()} if 'shared_with_roles' in item else {}
        },
        'last_modified': item.get('last_modified', {}).get('S', 'N/A'),
        'notes': item.get('notes', {}).get('S', ''),
        'tags': [] if item.get('tags', {}).get('SS', ['NONE'])[0] == 'NONE' else item.get('tags', {}).get('SS', []),
        'favorite': item.get('favorite', {}).get('BOOL', False),
        'version': int(item.get('version', {}).get('N', 1))
    }


def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded = verify_token(token)

        user_id = decoded.get('sub')
        user_groups = decoded.get('cognito:groups', [])

        if not user_id:
            return format_response(400, {'message': 'Invalid token: Missing userId'})

        print(f"Fetching secrets for user: {user_id}")

        user_secrets_resp = dynamodb.query(
            TableName=f"{TABLE_PREFIX}passwords",
            KeyConditionExpression="user_id = :user_id",
            ExpressionAttributeValues={":user_id": {'S': user_id}}
        )
        user_secrets = [
            {**format_secret(item), 'owned_by_me': True}
            for item in user_secrets_resp.get('Items', [])
        ]
        print(f"User owns {len(user_secrets)} secrets")

        group_secrets = []
        if user_groups:
            for group in user_groups:
                response = dynamodb.query(
                    TableName=f"{TABLE_PREFIX}passwords",
                    IndexName="shared_with_groups-index",
                    KeyConditionExpression="shared_with_groups = :group_id",
                    ExpressionAttributeValues={":group_id": {'S': group}}
                )
                for item in response.get('Items', []):
                    if item['user_id']['S'] != user_id:
                        group_secrets.append({**format_secret(item), 'owned_by_me': False})

        print(f"User has access to {len(group_secrets)} secrets via groups")

        user_shared_resp = dynamodb.query(
            TableName=f"{TABLE_PREFIX}passwords",
            IndexName="shared_with_users-index",
            KeyConditionExpression="shared_with_users = :user_id",
            ExpressionAttributeValues={":user_id": {'S': user_id}}
        )
        user_shared_secrets = [
            {**format_secret(item), 'owned_by_me': item['user_id']['S'] == user_id}
            for item in user_shared_resp.get('Items', [])
        ]
        print(f"User has {len(user_shared_secrets)} secrets shared directly with them")

        all_secrets = user_secrets + group_secrets + user_shared_secrets

        unique_secrets = {}
        for secret in all_secrets:
            key = f"{secret['user_id']}-{secret['site']}-{secret['subdirectory']}"
            if key not in unique_secrets:
                unique_secrets[key] = secret
            else:
                existing = unique_secrets[key]
                existing['shared_with']['groups'] = list(set(existing['shared_with']['groups'] + secret['shared_with']['groups']))
                existing['shared_with']['users'] = list(set(existing['shared_with']['users'] + secret['shared_with']['users']))

        sorted_secrets = sorted(unique_secrets.values(), key=lambda x: x['site'].lower())
        print(f"Returning {len(sorted_secrets)} unique secrets")

        return format_response(200, {'secrets': sorted_secrets})
    except Exception as e:
        print("Error fetching secrets:", str(e))
        return format_response(500, {'message': str(e)})
