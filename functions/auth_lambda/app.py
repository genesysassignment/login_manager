import boto3
from base64 import b64decode
import os
from botocore.exceptions import ClientError

# DynamoDB client
dynamodb = boto3.client('dynamodb')

def lambda_handler(event, context):
    table_name = os.getenv('DYNAMODB_TABLE_NAME')
    
    # Get the Authorization header from the event
    auth_header = event['authorizationToken']
    
    if not auth_header or not auth_header.startswith('Basic '):
        return generate_policy('Deny', event['methodArn'])
    
    # Decode the Basic Auth credentials
    encoded_credentials = auth_header.split(' ')[1]
    decoded_credentials = b64decode(encoded_credentials).decode('utf-8')
    username, password = decoded_credentials.split(':')
    
    # Check the credentials in DynamoDB
    try:
        response = dynamodb.get_item(
            TableName=table_name,
            Key={
                'Username': {'S': username}
            }
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
        return generate_policy('Deny', event['methodArn'])

    if 'Item' not in response or response['Item']['Password']['S'] != password:
        return generate_policy('Deny', event['methodArn'])

    return generate_policy('Allow', event['methodArn'])

def generate_policy(effect, resource):
    return {
        'principalId': 'user',  # Placeholder value
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }
