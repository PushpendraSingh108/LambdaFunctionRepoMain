import boto3
import json
import csv
from io import StringIO
from datetime import datetime, timezone
import botocore.exceptions
import time
import math

# Constants
ORGANIZATION_ID = 'o-qXXXXXX'
ROLE_NAME = 'Assume_role_child_account'
S3_BUCKET_NAME = 'Bucket_Name'

# Initialize AWS SDK clients
sts_client = boto3.client('sts')
s3_client = boto3.client('s3')

def assume_role(account_id, role_name):
    try:
        print(account_id)
        response = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName='AssumeRoleSession'
        )
        return response['Credentials']
    except Exception as e:
        error_message = f"Error assuming role in account {account_id}: {str(e)}"
        print(error_message)
        return None

def get_user_tags(iam_client, username):
    try:
        response = iam_client.list_user_tags(UserName=username)
        tags = {tag['Key']: tag['Value'] for tag in response['Tags']}
        return tags
    except Exception as e:
        print(f"Error fetching tags for user {username}: {str(e)}")
        return {}

def process_account_with_retry(account_id, role_name, all_users_data):
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            return process_account(account_id, role_name, all_users_data)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ThrottlingException':
                print(f"Rate limit exceeded. Retrying after back-off... (Attempt {attempt}/{max_attempts})")
                time.sleep(math.pow(2, attempt))  # Exponential back-off
            else:
                raise

def process_account(account_id, role_name, all_users_data):
    role_credentials = assume_role(account_id, role_name)
    
    if role_credentials is None:
        return False  # Skip processing if role assumption fails

    try:
        session = boto3.Session(
            aws_access_key_id=role_credentials['AccessKeyId'],
            aws_secret_access_key=role_credentials['SecretAccessKey'],
            aws_session_token=role_credentials['SessionToken']
        )

        iam_client = session.client('iam')
        
        # Get account alias
        account_aliases = iam_client.list_account_aliases().get('AccountAliases', [])
        account_alias = account_aliases[0] if account_aliases else None

        # Paginate through list_users results
        paginator = iam_client.get_paginator('list_users')
        for response in paginator.paginate():
            for user in response['Users']:
                username = user['UserName']
                tags = get_user_tags(iam_client, username)
                
                creation_date = user['CreateDate']
                creation_date_aware = creation_date.replace(tzinfo=timezone.utc)
                age_in_days = (datetime.now(timezone.utc) - creation_date_aware).days
                
                user_data = {
                    'AccountID': account_id,
                    'AccountAlias': iam_client.list_account_aliases()['AccountAliases'][0],
                    'UserName': username,
                    'Tags': json.dumps(tags),
                    'CreationDateTime': user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S'),
                    'CreationAgeInDays': age_in_days
                }
                all_users_data.append(user_data)

        return True  # Successfully processed account
    except Exception as e:
        error_message = f"Error processing account {account_id}: {str(e)}"
        print(error_message)
        return False  # Failed to process account

def fetch_accounts_with_retry(org_client):
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            all_accounts = []
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                all_accounts.extend(page['Accounts'])
            return all_accounts
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ThrottlingException':
                print(f"Rate limit exceeded. Retrying after back-off... (Attempt {attempt}/{max_attempts})")
                time.sleep(math.pow(2, attempt))  # Exponential back-off
            else:
                raise

def lambda_handler(event, context):
    try:
        org_client = boto3.client('organizations')
        accounts = fetch_accounts_with_retry(org_client)
        
        
        success_accounts = []
        failed_accounts = []
        
        all_users_data = []
        
        for account in accounts:
            if process_account_with_retry(account['Id'], ROLE_NAME, all_users_data):
                print("true",account)
                success_accounts.append(account['Id'])
            else:
                print("else",account)
                failed_accounts.append(account['Id'])
                
            # # Breaking condition when we reach 200 accounts or there are no more accounts left
            # if len(all_users_data) >= 200 or len(all_users_data) == len(accounts):
            #     support_test=len(all_users_data) == len(accounts)
            #     print("len(all_users_data) == len(accounts)",support_test)
            #     support_test2=len(all_users_data) >= 200
            #     print("len(all_users_data) >= 200",support_test2)
            #     print("break")
            #     break

        current_datetime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        s3_key = f"IAM_USER_TAGS_{ORGANIZATION_ID}_{current_datetime}.csv"
        
        csv_buffer = StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(["AccountID", "AccountAlias", "UserName", "Tags", "CreationDateTime", "CreationAgeInDays"])

        for user_data in all_users_data:
            writer.writerow([user_data['AccountID'], user_data['AccountAlias'], user_data['UserName'], user_data['Tags'], user_data['CreationDateTime'], user_data['CreationAgeInDays']])
        
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=s3_key, Body=csv_buffer.getvalue())
        
        success_message = "Processing completed successfully."
        print(success_accounts)
        if success_accounts:
            success_message += f" Successfully processed accounts: {success_accounts}"
        
        if failed_accounts:
            success_message += f" Failed to process accounts: {failed_accounts}"
        
        return {
            'statusCode': 200,
            'body': json.dumps(success_message)
        }
    except Exception as e:
        error_message = f"Error in lambda_handler: {str(e)}"
        print(error_message)
        
        return {
            'statusCode': 500,
            'body': json.dumps(error_message)
        }
