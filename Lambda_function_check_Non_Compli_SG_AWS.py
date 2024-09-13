import boto3
import csv
import logging
from botocore.exceptions import ClientError
from botocore.config import Config
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AWS SDK configuration
config = Config(
    retries={
        'max_attempts': 3,
        'mode': 'adaptive'
    }
)

# Variables
organization_id = "o-xxxxxxx"
s3_bucket_name = "Bucket_Nmae"
assumed_role_name = "Assume_role_name"
accounts_per_second_limit = 9
batch_size = 5  # Reduced batch size for testing

# Function to assume role in another AWS account
def assume_role(account_id, role_name):
    sts_client = boto3.client('sts', config=config)
    try:
        role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='CrossAccountSession'
        )
        credentials = response['Credentials']
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken'],
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            logger.error(f"Access denied when assuming role in account {account_id}. Ensure that the trust policy allows sts:AssumeRole for the calling role. Error: {e}")
        else:
            logger.error(f"Failed to assume role in account {account_id}: {e}")
        return None

# Function to list all AWS regions
def list_aws_regions():
    ec2_client = boto3.client('ec2', config=config)
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    return regions

# Function to list security groups with specified inbound rules
def list_security_groups(account_id, account_name, credentials, region):
    ec2_client = boto3.client('ec2', region_name=region, **credentials, config=config)
    security_groups_info = []
    ipv4_ranges = ['0.0.0.0/0', '0.0.0.0/8', '0.0.0.0/16', '0.0.0.0/24', '0.0.0.0/32']
    ipv6_ranges = ['::/0', '::/16', '::/32', '::/48', '::/64']
    try:
        response = ec2_client.describe_security_groups()
        for group in response['SecurityGroups']:
            group_id = group['GroupId']
            group_name = group['GroupName']
            
            for permission in group['IpPermissions']:
                if permission['IpProtocol'] in ['-1', 'tcp', 'udp']:
                    # Check IPv4 ranges
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range['CidrIp'] in ipv4_ranges:
                            from_port = permission.get('FromPort', -1)
                            to_port = permission.get('ToPort', -1)
                            if from_port in [22, 3389, 3306, 5432, 1433, 465, 0] and to_port in [22, 3389, 3306, 5432, 1433, 465, 65535]:
                                rule_id = f"{group_id}-{permission['IpProtocol']}-{from_port}-{to_port}-{ip_range['CidrIp']}"
                                security_group_details = {
                                    'Account ID': account_id,
                                    'Account Name': account_name,
                                    'Region': region,
                                    'Security Group ID': group_id,
                                    'Security Group Name': group_name,
                                    'Rule ID': rule_id,
                                    'Port': f"{from_port}-{to_port}",
                                    'Protocol': permission['IpProtocol']
                                }
                                security_groups_info.append(security_group_details)
                    
                    # Check IPv6 ranges
                    for ipv6_range in permission.get('Ipv6Ranges', []):
                        if ipv6_range['CidrIpv6'] in ipv6_ranges:
                            from_port = permission.get('FromPort', -1)
                            to_port = permission.get('ToPort', -1)
                            if from_port in [22, 3389, 3306, 5432, 1433, 465, 0] and to_port in [22, 3389, 3306, 5432, 1433, 465, 65535]:
                                rule_id = f"{group_id}-{permission['IpProtocol']}-{from_port}-{to_port}-{ipv6_range['CidrIpv6']}"
                                security_group_details = {
                                    'Account ID': account_id,
                                    'Account Name': account_name,
                                    'Region': region,
                                    'Security Group ID': group_id,
                                    'Security Group Name': group_name,
                                    'Rule ID': rule_id,
                                    'Port': f"{from_port}-{to_port}",
                                    'Protocol': permission['IpProtocol']
                                }
                                security_groups_info.append(security_group_details)
    except ClientError as e:
        logger.error(f"Failed to retrieve security groups for account {account_id} in region {region}: {e}")
        raise e
    return security_groups_info

# Function to upload data to S3
def upload_data_to_s3(data, filename):
    try:
        csv_buffer = StringIO()
        fieldnames = ['Account ID', 'Account Name', 'Region', 'Security Group ID', 'Security Group Name', 'Rule ID', 'Port', 'Protocol']
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()
        for item in data:
            writer.writerow(item)

        s3_client = boto3.client('s3', config=config)
        s3_client.put_object(Body=csv_buffer.getvalue(), Bucket=s3_bucket_name, Key=filename)
    except ClientError as e:
        logger.error(f"Error uploading data to S3: {e}")
        raise e

# Function to upload failed account data to S3
def upload_failed_accounts_to_s3(data, filename):
    try:
        csv_buffer = StringIO()
        fieldnames = ['Account ID', 'Account Name', 'Failure Reason']
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()
        for item in data:
            writer.writerow(item)

        s3_client = boto3.client('s3', config=config)
        s3_client.put_object(Body=csv_buffer.getvalue(), Bucket=s3_bucket_name, Key=filename)
    except ClientError as e:
        logger.error(f"Error uploading failed account data to S3: {e}")
        raise e

# Function to process account
def process_account(account):
    account_id = account['Id']
    account_name = account['Name']
    regions = list_aws_regions()
    all_security_groups_info = []
    failure_reasons = []

    try:
        assumed_credentials = assume_role(account_id, assumed_role_name)
        if assumed_credentials:
            for region in regions:
                try:
                    security_groups_info = list_security_groups(account_id, account_name, assumed_credentials, region)
                    all_security_groups_info.extend(security_groups_info)
                except Exception as e:
                    logger.error(f"Failed to list security groups for account {account_id} in region {region}: {e}")
                    failure_reasons.append(f"Region {region}: {str(e)}")
            if all_security_groups_info:
                return all_security_groups_info, failure_reasons
            else:
                failure_reasons.append("No matching security groups found")
        else:
            logger.error(f"Failed to assume role in account {account_id}")
            failure_reasons.append("Failed to assume role")
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        failure_reasons.append(str(e))

    return [], failure_reasons

# Function to retrieve accounts within the organization
def get_organization_accounts(organization_id):
    orgs_client = boto3.client('organizations', config=config)
    try:
        paginator = orgs_client.get_paginator('list_accounts')
        accounts = [account for page in paginator.paginate(PaginationConfig={'PageSize': 20}) for account in page['Accounts']]
        return accounts
    except ClientError as e:
        logger.error(f"Error listing accounts in organization {organization_id}: {e}")
        return []

def lambda_handler(event, context):
    success_count = 0
    failure_count = 0
    all_accounts_security_groups_info = []
    all_failure_reasons = []
    failed_accounts_info = []

    # Get list of accounts
    accounts = get_organization_accounts(organization_id)
    logger.info(f"Total accounts retrieved: {len(accounts)}")

    # Process accounts in parallel batches
    for i in range(0, len(accounts), batch_size):
        batch = accounts[i:i + batch_size]
        logger.info(f"Processing batch {i//batch_size + 1}: {len(batch)} accounts")

        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            futures = {executor.submit(process_account, account): account for account in batch}
            for future in as_completed(futures):
                account = futures[future]
                try:
                    result, failure_reasons = future.result()
                    if result:
                        all_accounts_security_groups_info.extend(result)
                        success_count += 1
                    else:
                        logger.error(f"No security groups found for account {account['Id']}, failure reasons: {failure_reasons}")
                        all_failure_reasons.extend(failure_reasons)  # Aggregate failure reasons
                        failed_accounts_info.append({
                            'Account ID': account['Id'],
                            'Account Name': account['Name'],
                            'Failure Reason': '; '.join(failure_reasons)
                        })
                        failure_count += 1
                except Exception as e:
                    logger.error(f"Failed to process account {account['Id']}: {e}")
                    all_failure_reasons.append(str(e))  # Capture generic failure reason
                    failed_accounts_info.append({
                        'Account ID': account['Id'],
                        'Account Name': account['Name'],
                        'Failure Reason': str(e)
                    })
                    failure_count += 1

        # Ensure compliance with AWS rate limit
        logger.info("Sleeping for 1 second to comply with rate limit...")
        time.sleep(1 / accounts_per_second_limit)

    # Upload collected security group info to S3
    if all_accounts_security_groups_info:
        filename = f"Security_Groups_Non_Compliant_{datetime.now().strftime('%Y-%m-%d')}.csv"
        upload_data_to_s3(all_accounts_security_groups_info, filename)

    # Upload failed account info to S3
    if failed_accounts_info:
        failed_filename = f"Failed_Accounts_{datetime.now().strftime('%Y-%m-%d')}.csv"
        upload_failed_accounts_to_s3(failed_accounts_info, failed_filename)

    # Log success and failure counts
    logger.info(f"Success count: {success_count}")
    logger.info(f"Failure count: {failure_count}")

    # Log detailed failure reasons for all failed accounts
    for reason in all_failure_reasons:
        logger.error(f"Failure reason: {reason}")

    # Return success or failure status
    return {
        'statusCode': 200,
        'body': f"Success count: {success_count}, Failure count: {failure_count}"
    }
