##This Lambda function lists all EC2 instances across multiple AWS accounts within an OU
#It assumes a role in each child account to retrieve EC2 instance details,
#including instance ID, type, state, launch time, and associated tags.

import boto3
import csv
from io import StringIO
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Variable parameters
ou_id = "ou-XXXXXXXXX"   #OU_ID
assume_role_name = "AssumeChildRole"  
s3_bucket_name = "bucket_Name"  

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

# Create AWS clients
session = boto3.Session()
org_client = session.client('organizations', region_name='us-east-1')
sts_client = session.client('sts')
s3_client = session.client('s3')

# Function to list child accounts by OU ID with pagination handling
def list_child_accounts_by_ou(ou_id):
    try:
        accounts = []
        paginator = org_client.get_paginator('list_accounts_for_parent')
        for page in paginator.paginate(ParentId=ou_id):
            accounts.extend(page['Accounts'])
        return accounts
    except ClientError as e:
        logger.error(f"Error listing child accounts for OU {ou_id}: {e}")
        return []

# Function to assume role
def assume_role(account_id, role_name):
    try:
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumedRoleSession"
        )
        return assumed_role['Credentials']
    except ClientError as e:
        logger.error(f"Error assuming role in account {account_id}: {e}")
        return None

# Function to list all regions
def list_all_regions(ec2_client):
    try:
        return [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    except ClientError as e:
        logger.error(f"Error listing regions: {e}")
        return []

# Function to get instances in various states in a region
def get_all_instances(ec2_client):
    try:
        reservations = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'terminated']}]
        )['Reservations']

        # Filter out terminated instances older than 15 days
        fifteen_days_ago = datetime.utcnow() - timedelta(days=15)
        filtered_instances = []
        for reservation in reservations:
            for instance in reservation['Instances']:
                if instance['State']['Name'] == 'terminated':
                    if instance['StateTransitionReason'] and 'User initiated' in instance['StateTransitionReason']:
                        termination_date_str = instance['StateTransitionReason'].split('(')[1].strip(')')
                        termination_date = datetime.strptime(termination_date_str, '%Y-%m-%d %H:%M:%S GMT')
                        if termination_date < fifteen_days_ago:
                            continue
                filtered_instances.append(instance)
        return filtered_instances
    except ClientError as e:
        logger.error(f"Error retrieving instances: {e}")
        return []

# Function to get account name
def get_account_name(account_id):
    try:
        response = org_client.describe_account(AccountId=account_id)
        return response['Account']['Name']
    except ClientError as e:
        logger.error(f"Error retrieving account name for Account: {account_id}: {e}")
        return "Error"

# Function to get organizational unit
def get_organizational_unit(account_id):
    try:
        response = org_client.list_parents(ChildId=account_id)
        return response['Parents'][0]['Id']
    except ClientError as e:
        logger.error(f"Error retrieving organizational unit for Account: {account_id}: {e}")
        return "Error"

# Function to get image description
def get_image_description(ec2_client, image_id):
    try:
        response = ec2_client.describe_images(ImageIds=[image_id])
        if response['Images']:
            return response['Images'][0].get('Description', '')
        else:
            return ''
    except ClientError as e:
        logger.error(f"Error retrieving image description for Image ID {image_id}: {e}")
        return ''

# Function to upload CSV data directly to S3
def upload_csv_to_s3(results):
    current_date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f'EC2_ListAllAccounts_Confidential_Restricted_OU.csv'
    s3_resource = boto3.resource('s3')
    s3_object = s3_resource.Object(s3_bucket_name, filename)

    # Write data directly to S3 object
    with StringIO() as output:
        writer = csv.DictWriter(output, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
        s3_object.put(Body=output.getvalue())
    
    logger.info(f"CSV uploaded to S3 successfully: {filename}")

# Function to process a single account
def process_account(account):
    account_id = account['Id']
    account_name = get_account_name(account_id)
    organizational_unit = get_organizational_unit(account_id)
    credentials = assume_role(account_id, assume_role_name)
    
    if not credentials:
        return (account_id, "Failed to assume role", None)

    results = []
    no_instances_found = True
    try:
        for region in list_all_regions(session.client('ec2', region_name='us-east-1')):
            session_assumed = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=region
            )
            ec2_client_assumed = session_assumed.client('ec2')
            try:
                instances = get_all_instances(ec2_client_assumed)
                if instances:
                    no_instances_found = False
                for instance in instances:
                    image_description = get_image_description(ec2_client_assumed, instance['ImageId'])
                    instance_details = {
                        'Account ID': account_id,
                        'Account Name': account_name,
                        'Organizational Unit': organizational_unit,
                        'Region Name': region,
                        'Export DateTime': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'Instance ID': instance['InstanceId'],
                        'Name': next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), None),
                        'Availability Zone': instance['Placement']['AvailabilityZone'],
                        'State': instance['State']['Name'],
                        'Vpc ID': instance.get('VpcId', ''),
                        'Instance Type': instance['InstanceType'],
                        'Launch DateTime': instance['LaunchTime'].strftime("%Y-%m-%d %H:%M:%S"),
                        'Platform': instance.get('Platform', 'Linux/UNIX'),
                        'Image ID': instance['ImageId'],
                        'Image Description': image_description,
                        'Public IP Address': instance.get('PublicIpAddress', ''),
                        'Public DNS Name': instance.get('PublicDnsName', ''),
                        'Private IP Address': instance.get('PrivateIpAddress', ''),
                        'Private DNS Name': instance.get('PrivateDnsName', ''),
                        'Mac Address(s)': ', '.join(ni['MacAddress'] for ni in instance.get('NetworkInterfaces', [])),
                        'Tag(s)': ', '.join(f"{tag['Key']}={tag['Value']}" for tag in instance.get('Tags', []))
                    }
                    results.append(instance_details)
            except ClientError as e:
                logger.error(f"Error retrieving instances for account {account_id} in region {region}: {str(e)}")
                return (account_id, str(e), None)
        if no_instances_found:
            return (account_id, "No EC2 instances found", None)
        return (account_id, None, results)
    except Exception as e:
        logger.error(f"Error processing account {account_id}: {str(e)}")
        return (account_id, str(e), None)

# Lambda handler
def lambda_handler(event, context):
    results = []
    processed_accounts = 0
    failed_accounts = []
    authentication_failures = []
    processing_failures = []
    no_instances_accounts = []

    accounts = list_child_accounts_by_ou(ou_id)
    logger.info(f"Total accounts to process: {len(accounts)}")

    # Process up to 10 accounts in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_account, account): account for account in accounts}
        for future in as_completed(futures):
            account_id, error, account_results = future.result()
            if error:
                if error == "Failed to assume role":
                    authentication_failures.append(account_id)
                elif error == "No EC2 instances found":
                    no_instances_accounts.append(account_id)
                else:
                    processing_failures.append((account_id, error))
            else:
                results.extend(account_results)
                processed_accounts += 1
                logger.info(f"Successfully processed account {account_id}")

    # Upload CSV to S3 if there are results
    if results:
        upload_csv_to_s3(results)

    summary_message = (f"Processed {processed_accounts} accounts successfully. "
                       f"Failed accounts due to authentication: {len(authentication_failures)}. "
                       f"Failed accounts due to processing errors: {len(processing_failures)}. "
                       f"Accounts with no EC2 instances: {len(no_instances_accounts)}.")

    logger.info(summary_message)
    
    # Invoke the CONCATE Lambda
    lambda_client = boto3.client('lambda')
    response = lambda_client.invoke(
        FunctionName='Cloudsecurity-concatenate-dailyEC2',
        InvocationType='Event'
    )
    logger.info("CONCATE Lambda invoked")

    return {
        'statusCode': 200,
        'body': summary_message,
        'authentication_failures': authentication_failures,
        'processing_failures': processing_failures,
        'no_instances_accounts': no_instances_accounts
    }
