##Tagging Users:-----
#The code processes each mapped account to list all IAM users.
#For each user, it retrieves the existing tags.
#It then checks if the user already has an "owner" tag or similar ("owner", "Owner", "OWNER").
#If the "owner" tag exists and contains the domain "@precisely.com", the user is skipped.
#If the "owner" tag exists but does not contain "@precisely.com", the user is skipped.
#If the "owner" tag does not exist, it creates a new tag called "owner" with the combined owner emails and adds it to the user.
##Handling Existing "Owner" Tags:---
#If an "owner" tag exists and matches the domain "@precisely.com", the user is skipped and recorded in the skipped users list with the reason "Existing owner tag with value ...".
#If an "owner" tag exists but does not match the domain "@precisely.com", the user is skipped and recorded in the skipped users list with the reason "Existing owner tag with non-@precisely.com value ...".
#If no "owner" tag exists, a new "owner" tag is added with the appropriate owner emails, and the user is recorded in the tagged users list.
# epoch time is added to the filenames

import boto3
import io
import csv
import re
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError
from botocore.config import Config
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

# Configuration for boto3 clients to handle rate limiting
boto_config = Config(retries={'max_attempts': 10, 'mode': 'standard'})

# Variables 
ASSUME_ROLE_NAME = 'ChildRole'
S3_BUCKET_NAME = 'bucketName'

# Initialize AWS clients
sts_client = boto3.client('sts', config=boto_config)
s3_client = boto3.client('s3', config=boto_config)

def lambda_handler(event, context):
    # Mapping of account IDs to owner emails
    account_email_mapping = {
'00xx29xx87': ['xvxvxvxvxvxv@pppppp.com'],
}

    tagged_users = []
    skipped_users = []

    processed_accounts = 0
    failed_accounts = 0
    accounts_with_new_tags = 0

    # List of specific AWS account IDs to process
    account_ids_to_process = account_email_mapping.keys()

    try:
        # Process accounts in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_account = {executor.submit(process_account, account_id, account_email_mapping[account_id]): account_id for account_id in account_ids_to_process}

            results = []
            for future in as_completed(future_to_account):
                account_id = future_to_account[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result['Status'] == 'Processed':
                        processed_accounts += 1
                        if result['TaggedUsers']:
                            accounts_with_new_tags += 1
                        tagged_users.extend(result['TaggedUsers'])
                        skipped_users.extend(result['SkippedUsers'])
                    else:
                        failed_accounts += 1
                except Exception as e:
                    failed_accounts += 1
                    logger.error(f'Error processing account {account_id}: {e}')

    except ClientError as e:
        logger.error(f'Error processing accounts: {e}')
        return {'statusCode': 500, 'body': str(e)}

    # Generate CSV files and upload to S3
    tagged_csv = generate_csv(tagged_users, ['AccountId', 'AccountName', 'UserName', 'NewTags', 'AllTags'])
    skipped_csv = generate_csv(skipped_users, ['AccountId', 'AccountName', 'UserName', 'Reason', 'AllTags'])

    # Include the current date and epoch time in the filenames
    current_date = datetime.now().strftime('%Y-%m-%d')
    epoch_time = int(time.time())
    upload_to_s3(tagged_csv, f'tagged_users_{current_date}_{epoch_time}.csv')
    upload_to_s3(skipped_csv, f'skipped_users_{current_date}_{epoch_time}.csv')


    logger.info(f'Processed {processed_accounts} accounts successfully.')
    logger.info(f'Failed to process {failed_accounts} accounts.')

    return {
        'statusCode': 200,
        'body': f'CSV files generated and uploaded to S3. Processed {processed_accounts} accounts successfully, of which {accounts_with_new_tags} accounts had new tags added. Failed to process {failed_accounts} accounts.'
    }

def assume_role(role_arn):
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='TagIAMUsersSession'
        )
        return response['Credentials']
    except ClientError as e:
        logger.error(f'Error assuming role {role_arn}: {e}')
        raise

def list_user_tags_with_retries(iam_client, user_name, retries=5):
    attempt = 0
    while attempt < retries:
        try:
            return iam_client.list_user_tags(UserName=user_name)
        except ClientError as e:
            if e.response['Error']['Code'] in ['Throttling', 'RequestLimitExceeded']:
                logger.warning(f'Throttling error on list_user_tags for user {user_name}, retrying ({attempt+1}/{retries})...')
                time.sleep(2 ** attempt)
                attempt += 1
            else:
                logger.error(f'Unexpected error on list_user_tags for user {user_name}: {e}')
                raise
    raise Exception(f'Failed to list tags for user {user_name} after {retries} retries')

def tag_user_with_retries(iam_client, user_name, tags, retries=5):
    attempt = 0
    while attempt < retries:
        try:
            iam_client.tag_user(UserName=user_name, Tags=tags)
            return
        except ClientError as e:
            if e.response['Error']['Code'] in ['Throttling', 'RequestLimitExceeded']:
                logger.warning(f'Throttling error on tag_user for user {user_name}, retrying ({attempt+1}/{retries})...')
                time.sleep(2 ** attempt)
                attempt += 1
            else:
                logger.error(f'Unexpected error on tag_user for user {user_name}: {e}')
                raise
    raise Exception(f'Failed to tag user {user_name} after {retries} retries')

def process_account(account_id, owner_emails):
    try:
        # Initialize Organizations client
        org_client = boto3.client('organizations', config=boto_config)
        
        # Retrieve account information
        account_info = org_client.describe_account(AccountId=account_id)
        account_name = account_info['Account']['Name']

        role_arn = f'arn:aws:iam::{account_id}:role/{ASSUME_ROLE_NAME}'

        # Assume the specified role in the account
        assumed_role = assume_role(role_arn)

        # Initialize IAM client with assumed role credentials
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=assumed_role['AccessKeyId'],
            aws_secret_access_key=assumed_role['SecretAccessKey'],
            aws_session_token=assumed_role['SessionToken'],
            config=boto_config
        )

        # List all IAM users in the account
        paginator = iam_client.get_paginator('list_users')
        users = []
        for page in paginator.paginate():
            users.extend(page['Users'])

        tagged_users = []
        skipped_users = []

        for user in users:
            user_name = user['UserName']

            try:
                # List tags for the user
                existing_tags = list_user_tags_with_retries(iam_client, user_name)
                existing_tags_dict = {tag['Key']: tag['Value'] for tag in existing_tags['Tags']}
                all_tags_str = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in existing_tags['Tags']])

                # Check if the user already has an 'owner' tag with the correct domain
                owner_tag_value = None
                owner_tag_found = False
                for tag_key in ['owner', 'Owner', 'OWNER']:
                    if tag_key in existing_tags_dict:
                        owner_tag_value = existing_tags_dict[tag_key]
                        owner_tag_found = True
                        break

                if owner_tag_found:
                    if '@precisely.com' in owner_tag_value:
                        skipped_users.append({
                            'AccountId': account_id,
                            'AccountName': account_name,
                            'UserName': user_name,
                            'Reason': f'Existing owner tag with value {owner_tag_value}',
                            'AllTags': all_tags_str
                        })
                        logger.info(f'Skipping user {user_name} in account {account_id}: existing owner tag with @precisely.com.')
                    else:
                        skipped_users.append({
                            'AccountId': account_id,
                            'AccountName': account_name,
                            'UserName': user_name,
                            'Reason': f'Existing owner tag with value {owner_tag_value} not containing @precisely.com',
                            'AllTags': all_tags_str
                        })
                        logger.info(f'Skipping user {user_name} in account {account_id}: existing owner tag not containing @precisely.com.')
                    continue

                # Combine owner emails into a single tag value
                owner_tag_value = ';'.join(owner_emails)
                new_tag_key = 'owner'
                if new_tag_key in existing_tags_dict and existing_tags_dict[new_tag_key] == owner_tag_value:
                    skipped_users.append({
                        'AccountId': account_id,
                        'AccountName': account_name,
                        'UserName': user_name,
                        'Reason': f'Existing {new_tag_key} tag with correct value {owner_tag_value}',
                        'AllTags': all_tags_str
                    })
                    logger.info(f'Skipping user {user_name} in account {account_id}: existing {new_tag_key} tag with correct value.')
                    continue

                tags_to_add = [{'Key': new_tag_key, 'Value': owner_tag_value}]
                tag_user_with_retries(iam_client, user_name, tags_to_add)

                tagged_users.append({
                    'AccountId': account_id,
                    'AccountName': account_name,
                    'UserName': user_name,
                    'NewTags': f'{new_tag_key}={owner_tag_value}',
                    'AllTags': all_tags_str
                })
                logger.info(f'Successfully tagged user {user_name} in account {account_id}')
            except ClientError as e:
                logger.error(f'Error tagging user {user_name} in account {account_id}: {e}')
                skipped_users.append({
                    'AccountId': account_id,
                    'AccountName': account_name,
                    'UserName': user_name,
                    'Reason': f'Error tagging user: {e}',
                    'AllTags': all_tags_str
                })

        return {
            'AccountId': account_id,
            'AccountName': account_name,
            'TaggedUsers': tagged_users,
            'SkippedUsers': skipped_users,
            'Status': 'Processed'
        }

    except Exception as e:
        logger.error(f'Failed to process account {account_id}: {e}')
        return {
            'AccountId': account_id,
            'Status': 'Failed',
            'Error': str(e)
        }


def generate_csv(data, headers):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    writer.writerows(data)
    return output.getvalue()

def upload_to_s3(csv_content, file_name):
    try:
        s3_client.put_object(Body=csv_content, Bucket=S3_BUCKET_NAME, Key=file_name)
        logger.info(f'Successfully uploaded {file_name} to S3 bucket {S3_BUCKET_NAME}')
    except ClientError as e:
        logger.error(f'Error uploading {file_name} to S3: {e}')
        raise