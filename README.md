# AWS Security Group Compliance Checker

## Overview
This project is an AWS Lambda function designed to check security groups in multiple AWS accounts for non-compliant rules. Specifically, it scans for open ports to public IP ranges (like `0.0.0.0/0`) for certain sensitive ports (e.g., 22, 3389, 3306). The script assumes an IAM role in each AWS account to retrieve security group details from all regions, logs results, and uploads the findings to an S3 bucket.

## Features
- **Cross-account Role Assumption:** The script assumes a specified IAM role in multiple AWS accounts within an AWS Organization to collect data.
- **Region-wise Scanning:** The script checks for security group rules across all AWS regions in each account.
- **Concurrent Execution:** Multiple accounts are processed in parallel using Python's `ThreadPoolExecutor`, allowing for fast data collection.
- **Compliance Check:** Detects open ports to public IP ranges for sensitive services such as SSH (port 22), RDP (3389), MySQL (3306), and others.
- **Detailed Logging:** Logs success and failure for each account, including specific failure reasons when the script cannot retrieve data.
- **Results Storage:** Stores the results in CSV format in an S3 bucket for both compliant and non-compliant security groups and failed accounts.

## Prerequisites
- Python 3.x
- AWS Lambda execution environment or any Python environment with AWS credentials.
- IAM role with `sts:AssumeRole`, `ec2:DescribeSecurityGroups`, `organizations:ListAccounts`, and `s3:PutObject` permissions.
- An AWS S3 bucket for storing results.

## Configuration
Before running the script, ensure the following variables are correctly set:
- **`organization_id`:** Your AWS Organization ID.
- **`s3_bucket_name`:** The name of the S3 bucket where results will be uploaded.
- **`assumed_role_name`:** The name of the IAM role assumed in target accounts for cross-account access.
- **`accounts_per_second_limit`:** Set to limit the rate at which accounts are processed (to avoid throttling by AWS).
- **`batch_size`:** Number of accounts processed in parallel batches.

## Deployment
1. Clone the repository and upload the Lambda function to AWS.
2. Set the environment variables (`organization_id`, `s3_bucket_name`, etc.) in the Lambda configuration.
3. Grant the Lambda execution role necessary permissions for assuming roles in other accounts and accessing S3.
4. Trigger the Lambda function based on your preferred schedule (e.g., daily or weekly).

## Usage
This script can be run within an AWS Lambda function or locally:
- **Locally**: Run with AWS credentials that have `sts:AssumeRole` and `organizations:ListAccounts` access.
- **In Lambda**: Deploy the script as a Lambda function in an account with appropriate permissions.

### Sample Invocation
```python
event = {}
context = {}
lambda_handler(event, context)
```

## Output
The Lambda function generates two CSV files:
1. **Security Groups Non-Compliant CSV**: Lists all security groups with non-compliant rules.
2. **Failed Accounts CSV**: Lists accounts that failed during processing, along with failure reasons.

These files are uploaded to the specified S3 bucket.

## Error Handling
- **Role Assumption Failure**: If the role cannot be assumed in a specific account, the error is logged, and the account is marked as failed.
- **API Limits**: The script ensures compliance with AWS rate limits by pausing between account batches.

## Logs
The script provides detailed logging for each account and region processed, including:
- Successful scans
- Security groups found
- Accounts where the role assumption or scanning failed

