import json
import os
import jwt
import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.client('dynamodb')
TABLE_PREFIX = os.environ.get('TABLE_PREFIX', 'RunaVault_')


def get_auth_token(event):
    """Extract the authentication token from the event."""
    headers = event.get('headers', {})
    auth_header = headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return None


def verify_token(token):
    """Verify the JWT token (simplified for this example)."""
    if not token:
        raise ValueError('Unauthorized: No token provided')
    try:
        # In a real application, you would verify the token with the public key
        decoded = jwt.decode(token, algorithms=['RS256'], options={'verify_signature': False})
        return decoded
    except Exception as e:
        raise ValueError(f'Unauthorized: {str(e)}')


def format_response(status_code, body):
    """Format the response to be returned by the Lambda."""
    return {
        'statusCode': status_code,
        'body': json.dumps(body),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }


def parse_body(body):
    """Parse the body of the request."""
    if isinstance(body, str):
        return json.loads(body) if body else {}
    return body or {}


def lambda_handler(event, context):
    try:
        token = get_auth_token(event)
        decoded = verify_token(token)

        user_claims = event.get('requestContext', {}).get('authorizer', {}).get('jwt', {}).get('claims', {})
        if not user_claims or not user_claims.get('sub'):
            return format_response(403, {'message': 'Forbidden - Invalid Token'})

        user_id = user_claims['sub']
        body = parse_body(event.get('body', {}))
        if not body.get('site'):
            return format_response(400, {'message': 'Missing site parameter'})

        site = body.get('site')
        subdirectory = body.get('subdirectory', '')

        user_groups = user_claims.get('cognito:groups', [])
        if isinstance(user_groups, str):
            try:
                if not user_groups.startswith('['):
                    user_groups = [g for g in user_groups.split(' ') if g]
                else:
                    parsed_groups = json.loads(user_groups.replace(r'(\w+)\s(\w+)', '["$1", "$2"]'))
                    user_groups = parsed_groups if isinstance(parsed_groups, list) else [user_groups]
            except Exception:
                user_groups = [g for g in user_groups.split(' ') if g] if ' ' in user_groups else [user_groups]
        user_groups = [group.strip('[]') for group in user_groups if group]

        effective_subdirectory = '' if subdirectory == 'default' else subdirectory
        composite_key = f"{site}{'#' + effective_subdirectory if effective_subdirectory else ''}"

        dynamo_response = dynamodb.get_item(
            TableName=f"{TABLE_PREFIX}passwords",
            Key={
                'user_id': {'S': user_id},
                'site': {'S': composite_key}
            }
        )

        item = dynamo_response.get('Item')
        owner_id = user_id
        encrypted_password_data = item.get('password', {}).get('S') if item else None

        if not item:
            query_response = dynamodb.query(
                TableName=f"{TABLE_PREFIX}passwords",
                KeyConditionExpression="user_id = :user_id AND site = :site",
                ExpressionAttributeValues={
                    ":user_id": {'S': user_id},
                    ":site": {'S': composite_key}
                }
            )
            item = query_response.get('Items', [{}])[0] if query_response.get('Items') else None
            if item:
                encrypted_password_data = item.get('password', {}).get('S')

        if not item and user_groups:
            for group in user_groups:
                group_query_response = dynamodb.query(
                    TableName=f"{TABLE_PREFIX}passwords",
                    IndexName="shared_with_groups-index",
                    KeyConditionExpression="shared_with_groups = :group_id",
                    FilterExpression="subdirectory = :subdirectory",
                    ExpressionAttributeValues={
                        ":group_id": {'S': group},
                        ":subdirectory": {'S': effective_subdirectory or 'default'}
                    }
                )

                matching_secret = next((i for i in group_query_response.get('Items', []) if i['site']['S'].split('#')[0] == site), None)
                if matching_secret:
                    owner_id = matching_secret['user_id']['S']
                    item = matching_secret
                    parsed_password_data = json.loads(item['password']['S'])
                    group_encrypted_password = next((g.get('encryptedPassword') for g in parsed_password_data.get('sharedWith', {}).get('groups', []) if g.get('groupId') == group), None)
                    encrypted_password_data = json.dumps({
                        'encryptedPassword': group_encrypted_password or parsed_password_data.get('encryptedPassword'),
                        'sharedWith': parsed_password_data.get('sharedWith', {})
                    })
                    break

        if not item:
            return format_response(404, {'message': 'Password not found'})

        username = item['username']['S']
        stored_subdirectory = item.get('subdirectory', {}).get('S', 'default')

        if not encrypted_password_data:
            return format_response(500, {'message': 'Secret data is incomplete in the database'})

        return format_response(200, {
            'site': site,
            'username': username,
            'subdirectory': stored_subdirectory,
            'password': encrypted_password_data
        })
    except ClientError as e:
        print(f"Error: {e}")
        status_code = 401 if 'Unauthorized' in str(e) else 403 if 'Forbidden' in str(e) else 500
        return format_response(status_code, {'message': str(e) or 'Internal Server Error'})
    except Exception as e:
        print(f"Error: {e}")
        status_code = 401 if 'Unauthorized' in str(e) else 403 if 'Forbidden' in str(e) else 500
        return format_response(status_code, {'message': str(e) or 'Internal Server Error'})
