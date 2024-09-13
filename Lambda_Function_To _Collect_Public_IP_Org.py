import boto3
import logging
from botocore.exceptions import ClientError
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from openpyxl import Workbook
from io import BytesIO
import time

# Variable parameters
organization_id = "o-xxxxxxxxx"
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

# Function to list child accounts
def list_child_accounts():
    try:
        accounts = []
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])
        return accounts
    except ClientError as e:
        logger.error(f"Error listing child accounts: {e}")
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

# Function to get network interfaces in a region
def get_network_interfaces(ec2_client):
    try:
        return ec2_client.describe_network_interfaces()['NetworkInterfaces']
    except ClientError as e:
        logger.error(f"Error retrieving network interfaces: {e}")
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

# Function to upload Excel data directly to S3
def upload_excel_to_s3(results):
    current_date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f'List_All_Public-IP.xlsx'
    s3_resource = boto3.resource('s3')
    s3_object = s3_resource.Object(s3_bucket_name, filename)

    # Create a workbook and add a worksheet
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Public IP Addresses"

    # Write headers
    headers = list(results[0].keys())
    sheet.append(headers)

    # Write data rows
    for row in results:
        sheet.append(list(row.values()))

    # Save the workbook to a bytes buffer
    buffer = BytesIO()
    workbook.save(buffer)
    buffer.seek(0)

    # Upload the buffer content to S3
    s3_object.put(Body=buffer.getvalue())

    logger.info(f"Excel file uploaded to S3 successfully: {filename}")

# Function to process a single account
def process_account(account):
    account_id = account['Id']
    account_name = get_account_name(account_id)
    organizational_unit = get_organizational_unit(account_id)
    credentials = assume_role(account_id, assume_role_name)

    if not credentials:
        return (account_id, "Failed to assume role", None, False)

    results = []
    found_public_ip = False
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
                network_interfaces = get_network_interfaces(ec2_client_assumed)
                for interface in network_interfaces:
                    public_ip = interface.get('Association', {}).get('PublicIp', '')
                    if public_ip:  # Only add to results if there's a public IP
                        found_public_ip = True
                        interface_details = {
                            'Account ID': account_id,
                            'Account Name': account_name,
                            'Organizational Unit': organizational_unit,
                            'Region Name': region,
                            'Public IP Address': public_ip,
                            'Network Interface ID': interface['NetworkInterfaceId'],
                            'Attachment ID': interface.get('Attachment', {}).get('AttachmentId', ''),
                            'Resource ID': interface.get('Attachment', {}).get('InstanceId', 'N/A'),
                            'Description': interface.get('Description', ''),
                            'Availability Zone': interface.get('AvailabilityZone', '')
                        }
                        results.append(interface_details)
            except ClientError as e:
                logger.error(f"Error retrieving network interfaces for account {account_id} in region {region}: {str(e)}")
                return (account_id, str(e), None, False)

        return (account_id, None, results, found_public_ip)
    except Exception as e:
        logger.error(f"Error processing account {account_id}: {str(e)}")
        return (account_id, str(e), None, False)

# Rate limiting function
def rate_limit_execution(executor, accounts, max_calls_per_second=10):
    results = []
    processed_accounts = 0
    failed_accounts = []
    no_public_ip_accounts = []
    batch_size = max_calls_per_second
    for i in range(0, len(accounts), batch_size):
        batch = accounts[i:i+batch_size]
        futures = {executor.submit(process_account, account): account for account in batch}
        for future in as_completed(futures):
            account_id, error, account_results, found_public_ip = future.result()
            if error:
                failed_accounts.append((account_id, error))
            else:
                if not found_public_ip:
                    no_public_ip_accounts.append(account_id)
                results.extend(account_results)
                processed_accounts += 1
        # Wait for 1 second before processing the next batch
        time.sleep(1)
    return results, processed_accounts, failed_accounts, no_public_ip_accounts

# Lambda handler
def lambda_handler(event, context):
    accounts = list_child_accounts()

    # Process accounts in parallel with rate limiting
    with ThreadPoolExecutor(max_workers=50) as executor:
        results, processed_accounts, failed_accounts, no_public_ip_accounts = rate_limit_execution(executor, accounts)

    # Upload Excel to S3 if there are results
    if results:
        upload_excel_to_s3(results)

    summary_message = (
        f"Processed {processed_accounts} accounts successfully. "
        f"Failed accounts: {len(failed_accounts)}. "
        f"Accounts with no public IPs: {len(no_public_ip_accounts)} - {no_public_ip_accounts}"
    )
    logger.info(summary_message)

    if failed_accounts:
        for account_id, reason in failed_accounts:
            logger.error(f"Account ID: {account_id} failed with reason: {reason}")
            
    # Invoke the METADATAIP Lambda
    lambda_client = boto3.client('lambda')
    response = lambda_client.invoke(
        FunctionName='Cloudsecurity-Add_Metadata-daily-IP_Function',
        InvocationType='Event'
    )
    logger.info("METADATAIP Lambda invoked")

    return {
        'statusCode': 200,
        'body': summary_message
    }
