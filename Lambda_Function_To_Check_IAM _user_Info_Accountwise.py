import boto3
import json
import csv
from io import StringIO
from datetime import datetime, timezone
import botocore.exceptions
import time
import math

# Constants
ORGANIZATION_ID = 'o-xxxxxxxxxxx'
ROLE_NAME = 'Assume_Role_Child_Account'
S3_BUCKET_NAME = 'Bucket_Name'

# Initialize AWS SDK clients
sts_client = boto3.client('sts')
s3_client = boto3.client('s3')

def assume_role(account_id, role_name):
    try:
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

                # Get access keys and their details
                access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
                if access_keys:
                    access_key = access_keys[0]  # Assuming only one active access key at a time for simplicity
                    access_key_id = access_key['AccessKeyId']
                    active_key_age = (datetime.now(timezone.utc) - access_key['CreateDate']).days
                    access_key_last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id).get('AccessKeyLastUsed')
                else:
                    access_key_id = ""
                    active_key_age = ""
                    access_key_last_used = ""

                # Get login profile for console access
                try:
                    login_profile = iam_client.get_login_profile(UserName=username)
                    console_last_sign_in = login_profile['LoginProfile']['CreateDate'].strftime('%Y-%m-%d %H:%M:%S')
                    console_access = True
                except iam_client.exceptions.NoSuchEntityException:
                    console_last_sign_in = ""
                    console_access = False

                # Get password age
                password_age = ""
                if 'PasswordLastUsed' in user:
                    password_age = (datetime.now(timezone.utc) - user['PasswordLastUsed']).days

                # Get ARN
                arn = user['Arn']

                # Get signing certificates
                signing_certs = json.dumps(iam_client.list_signing_certificates(UserName=username)['Certificates'])

                user_data = {
                    'AccountID': account_id,
                    'AccountAlias': account_alias,
                    'UserName': username,
                    'Tags': json.dumps(tags),
                    'CreationDateTime': user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S'),
                    'CreationAgeInDays': age_in_days,
                    'Path': user['Path'],
                    'Groups': json.dumps([group['GroupName'] for group in iam_client.list_groups_for_user(UserName=username)['Groups']]),
                    'MFAEnabled': len(iam_client.list_mfa_devices(UserName=username)['MFADevices']) > 0,
                    'LastActivity': str(access_key_last_used.get('LastUsedDate', '')),  # Convert datetime to string
                    'PasswordAge': str(password_age),  # Convert datetime to string
                    'ConsoleLastSignIn': str(console_last_sign_in),  # Convert datetime to string
                    'AccessKeyID': str(access_key_id),
                    'ActiveKeyAge': str(active_key_age),
                    'AccessKeyLastUsed': str(access_key_last_used),
                    'ARN': str(arn),
                    'ConsoleAccess': str(console_access),
                    'SigningCerts': signing_certs
                }
                
                all_users_data.append(user_data)

        return True  # Successfully processed account
    except Exception as e:
        error_message = f"Error processing account {account_id}: {str(e)}"
        print(error_message)
        return False  # Failed to process account

def lambda_handler(event, context):
    try:
        # Manually specify the child account IDs
        child_account_ids = ['402xxxxxxx', '77197xxxxxx',]

        success_accounts = []
        failed_accounts = []
        all_users_data = []

        for account_id in child_account_ids:
            if process_account_with_retry(account_id, ROLE_NAME, all_users_data):
                success_accounts.append(account_id)
            else:
                failed_accounts.append(account_id)

        current_datetime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        s3_key = f"IAM_USER_TAGS_{ORGANIZATION_ID}_combined_{current_datetime}.csv"

        csv_buffer = StringIO()
        writer = csv.writer(csv_buffer)
        
        writer.writerow(["AccountID", "AccountAlias", "UserName", "Tags", "CreationDateTime", "CreationAgeInDays", "Path", "Groups", "MFAEnabled",
                         "LastActivity", "PasswordAge", "ConsoleLastSignIn", "AccessKeyID", "ActiveKeyAge", "AccessKeyLastUsed", 
                         "ARN", "ConsoleAccess", "SigningCerts"])
        
        for user_data in all_users_data:
                writer.writerow([user_data['AccountID'], user_data['AccountAlias'], user_data['UserName'], user_data['Tags'], 
                             user_data['CreationDateTime'], user_data['CreationAgeInDays'], user_data['Path'], user_data['Groups'], 
                             user_data['MFAEnabled'], user_data['LastActivity'], user_data['PasswordAge'], 
                             user_data['ConsoleLastSignIn'], user_data['AccessKeyID'], user_data['ActiveKeyAge'], 
                             user_data['AccessKeyLastUsed'], user_data['ARN'], user_data['ConsoleAccess'], 
                             user_data['SigningCerts']])
        
        s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=s3_key, Body=csv_buffer.getvalue())

        success_message = "Processing completed successfully."
        
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
        
