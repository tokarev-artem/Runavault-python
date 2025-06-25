import os
import json
import re
import requests
from jose import jwt
from jose.exceptions import JWTError

USER_POOL_ID = os.environ["USER_POOL_ID"]
AWS_REGION = os.environ["AWS_REGION"]

JWKS_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json"
JWKS_KEYS = requests.get(JWKS_URL).json()["keys"]


def get_signing_key(kid):
    for key in JWKS_KEYS:
        if key["kid"] == kid:
            return key
    raise Exception("Public key not found in JWKS")


def verify_token(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise Exception("Invalid token: Missing key ID")
        signing_key = get_signing_key(kid)
        return jwt.decode(token, signing_key, algorithms=["RS256"], audience=None)
    except JWTError as e:
        raise Exception(f"Unauthorized: {str(e)}")


def format_response(status_code, body, headers=None):
    if headers is None:
        headers = {}
    response_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        **headers,
    }
    return {
        "statusCode": status_code,
        "body": json.dumps(body),
        "headers": response_headers,
    }


def sanitize_string(value):
    if not isinstance(value, str):
        return value
    replacements = {
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
        "\\": "&#92;",
        "`": "&#96;",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    return value


def sanitize_object(obj):
    if obj is None or not isinstance(obj, (dict, list)):
        return obj
    if isinstance(obj, list):
        return [sanitize_object(item) for item in obj]
    sanitized = {}
    for key, value in obj.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_string(value)
        elif isinstance(value, (dict, list)):
            sanitized[key] = sanitize_object(value)
        else:
            sanitized[key] = value
    return sanitized


def parse_body(body):
    if not body:
        raise Exception("No body provided")
    try:
        parsed = json.loads(body)
        return sanitize_object(parsed)
    except json.JSONDecodeError:
        raise Exception("Body is not valid JSON")


def get_auth_token(event):
    headers = event.get("headers", {})
    auth_header = headers.get("authorization") or headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise Exception("Unauthorized: No token provided")
    return auth_header.split(" ")[1]
