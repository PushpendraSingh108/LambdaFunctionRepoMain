# EC2 Instance Processing and Tagging Script

This project is an AWS Lambda function designed to process all AWS accounts within an Organizational Unit (OU) and retrieve a list of EC2 instances in various states (running, stopped, terminated). It also handles owner tagging and uploads the results to an S3 bucket in CSV format. Additionally, a "CONCATE" Lambda is invoked at the end for further processing.

## Features
1. **Account and EC2 Processing**: 
   - Retrieves all child accounts under a specified OU.
   - Assumes a specific IAM role in each account to list EC2 instances across all regions.
   - Filters out terminated instances older than 15 days.
   
2. **Instance Details**: 
   - Collects detailed information about each EC2 instance, including instance ID, state, VPC ID, tags, and more.
   - Fetches image descriptions for associated AMIs.

3. **Tagging Logic**:
   - Checks for an "owner" tag in each account.
   - Skips accounts if the "owner" tag contains the domain "@precisely.com".
   - Tags instances with the appropriate owner email if the tag is missing or does not match.

4. **Concurrency**:
   - Processes up to 10 AWS accounts in parallel using `ThreadPoolExecutor` for faster execution.

5. **Logging**: 
   - Provides detailed logging on the success or failure of account processing, including instances of authentication failure, processing errors, and accounts with no EC2 instances.

6. **Output**:
   - Generates a CSV file containing all instance details and uploads it to an S3 bucket.
   - Adds the current date and time to the filename for tracking.
   
7. **CONCATE Lambda Invocation**:
   - After the main process completes, the script invokes a "CONCATE" Lambda to handle the concatenation of results from multiple executions.

## Prerequisites
- AWS Lambda environment.
- IAM role (`AssumeChildRole`) with permissions to assume roles in other accounts.
- S3 bucket to store the output CSV.
- Proper organizational structure with accounts grouped under the specified OU.
  
## Configuration

### Variables
- `ou_id`: The Organizational Unit (OU) ID for processing child accounts.
- `assume_role_name`: IAM role name to assume in each child account.
- `s3_bucket_name`: Name of the S3 bucket where the results will be uploaded.

### Environment Variables (Optional)
- `AWS_REGION`: Specify the region where your Lambda function will run (default: `us-east-1`).
  
## Logging
- Logs are generated for each stage of the execution, including account processing, instance listing, and error handling.
- Successful and failed account processing is logged for future reference.

## How to Use

1. **Setup AWS Lambda**:
   - Deploy the script in AWS Lambda.
   - Set up the required permissions for the Lambda function to assume roles and access S3.

2. **Configure OU ID and IAM Role**:
   - Update the `ou_id` and `assume_role_name` variables to match your organization's setup.

3. **Invoke Lambda Function**:
   - The Lambda function can be triggered on-demand, by a scheduled event (e.g., daily), or via API Gateway.

4. **Output**:
   - The results will be uploaded to the specified S3 bucket in CSV format, with the timestamp included in the filename.

## Error Handling
- Accounts where role assumption fails are logged and added to the "authentication failures" list.
- Accounts that have no EC2 instances are tracked in a "no instances" list.
- General processing errors (e.g., region listing or instance fetching issues) are logged and reported.

## Future Improvements
- Implement retries with exponential backoff for failed operations.
- Add more granular tagging logic based on different domains or attributes.
- Extend functionality to support additional AWS resources.

