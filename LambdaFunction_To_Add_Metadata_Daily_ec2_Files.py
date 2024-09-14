import json
import boto3
import pandas as pd
import io
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

# Define S3 bucket names and file names
BUCKET1_NAME = 'dailyec2-bucket'
BUCKET2_NAME = 'accounts-master-bucket'
BUCKET3_NAME = 'dailyec2-metadata-bucket'
FILE1_NAME = 'Concatenate_EC2_ListAllAccounts/Concatenate_EC2_ListAllAccounts.csv'
FILE2_NAME = 'Accounts_Master.xlsx'
S3_REGION = 'us-east-1'  # Specify S3 region

# Initialize S3 client with region
s3 = boto3.client('s3', region_name=S3_REGION)

def lambda_handler(event, context):
    try:
        # Debug logging
        logger.info(f"Checking bucket: {BUCKET1_NAME}")
        logger.info(f"Checking bucket: {BUCKET2_NAME}")
        logger.info(f"Checking bucket: {BUCKET3_NAME}")

        # Load the first file from S3 (Bucket 1)
        obj1 = s3.get_object(Bucket=BUCKET1_NAME, Key=FILE1_NAME)
        content_type = obj1['ContentType']
        if content_type == 'text/csv' or content_type == 'binary/octet-stream':
            df1 = pd.read_csv(io.BytesIO(obj1['Body'].read()), encoding='utf-8')
            logger.info(f"DataFrame df1 loaded with shape: {df1.shape}")
        else:
            raise ValueError(f'Unsupported content type: {content_type}')

        # Ensure the second column is named 'Account Name'
        df1.columns = ['Account ID', 'Account Name'] + list(df1.columns[2:])
        logger.info(f"Account Names extracted with shape: {df1[['Account Name']].shape}")
        logger.info(f"Sample Account Names: {df1['Account Name'].head()}")

        # Load the second file from S3 (Bucket 2)
        obj2 = s3.get_object(Bucket=BUCKET2_NAME, Key=FILE2_NAME)

        # Check content type and read the Excel file
        if obj2['ContentType'] == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' or obj2['ContentType'] == 'binary/octet-stream':
            df2 = pd.read_excel(io.BytesIO(obj2['Body'].read()), sheet_name='AccountList', engine='openpyxl')
            logger.info(f"DataFrame df2 loaded with shape: {df2.shape}")
        else:
            raise ValueError(f'Unsupported content type: {obj2["ContentType"]}')

        # Select only the necessary columns from the second DataFrame
        columns_to_keep = [
            'Precisely Account Name', 'Status', 'Org', 'Cloud', 'Legacy Account Name',
            'Department (accounting)', 'Vendor Code', 'Product class', 'Business Unit', 
            'L2 Team', 'L3 Team', 'COGS', 'Use', 'Flag', 'Product Segment', 'Investment Segment', 
            'Product Name', 'Owner', 'Primary Technical Contact', 'Secondary Technical Contact', 
            'Additional Contacts'
        ]
        df2 = df2[columns_to_keep]
        logger.info(f"Filtered DataFrame df2 with shape: {df2.shape}")

        logger.info(f"Sample Precisely Account Names: {df2['Precisely Account Name'].head()}")

        # Merge using left join to retain all rows from df1 and add matching rows from df2
        merged_df = pd.merge(df1, df2, left_on='Account Name', right_on='Precisely Account Name', how='left')
        logger.info(f"Merged DataFrame with shape: {merged_df.shape}")

        # Save the merged DataFrame to an Excel file
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            merged_df.to_excel(writer, index=False, sheet_name='MergedData')
        output.seek(0)

        # Add current date and time to the file name
        current_datetime = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        merged_file_name = f'Metadata_All_EC2_File_{current_datetime}.xlsx'

        # Upload the merged file to S3 (Bucket 3)
        s3.put_object(Bucket=BUCKET3_NAME, Key=merged_file_name, Body=output.getvalue())

        return {
            'statusCode': 200,
            'body': json.dumps(f'Merged data saved to {merged_file_name} in bucket {BUCKET3_NAME}')
        }

    except Exception as e:
        error_message = f'Error: {str(e)}'
        import traceback
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'body': json.dumps(error_message)
        }
