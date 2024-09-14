# IAM User Data Collector

## Overview

This AWS Lambda function is designed to collect detailed information about IAM users across multiple AWS accounts. It assumes a specified role in each child account, gathers user data, and stores the results as a CSV file in an S3 bucket.

## Features

- **Role Assumption:** Uses AWS STS to assume a role in multiple AWS accounts.
- **User Data Collection:** Retrieves comprehensive information about IAM users including:
  - Tags associated with users.
  - Access key details (creation date, last used, etc.).
  - MFA status.
  - Console access status.
  - Password age and last sign-in details.
  - Signing certificates and groups.
- **Error Handling:** Retries role assumption and data collection using exponential backoff in case of throttling or rate-limit issues.
- **CSV Storage:** Stores the collected data in a CSV file in the specified S3 bucket.

## Prerequisites

- AWS Lambda configured with the necessary execution role to assume roles in child accounts.
- Permissions for the Lambda role to call `sts:AssumeRole`, `s3:PutObject`, `iam:*` actions across all accounts.
- An S3 bucket to store the output CSV files.

## Configuration

1. **Child Account IDs:** Add the child account IDs to be processed in the `child_account_ids` list in the code.
2. **Organization ID:** Set your organization ID in the `ORGANIZATION_ID` constant.
3. **Role Name:** Define the role name to assume in each child account via the `ROLE_NAME` constant.
4. **S3 Bucket Name:** Define the S3 bucket name where the results will be stored.

## Deployment

1. Zip the code and deploy it in AWS Lambda or upload directly using the AWS Lambda Console.
2. Set up the required IAM roles and policies for the Lambda function and child accounts.
3. Configure an event or schedule to trigger the Lambda function.

## Usage

Once deployed, the function will:
1. Assume the specified IAM role in each child account.
2. Collect user data (tags, access keys, MFA, etc.).
3. Store the output CSV in the specified S3 bucket.

## Example CSV Output

The CSV output will contain the following columns:
- AccountID
- AccountAlias
- UserName
- Tags
- CreationDateTime
- CreationAgeInDays
- Path
- Groups
- MFAEnabled
- LastActivity
- PasswordAge
- ConsoleLastSignIn
- AccessKeyID
- ActiveKeyAge
- AccessKeyLastUsed
- ARN
- ConsoleAccess
- SigningCerts

## Error Handling and Logging

- **Throttling:** The function handles `ThrottlingException` using an exponential backoff mechanism.
- **Logging:** Errors are logged to CloudWatch and error details are returned in the Lambda response.

## Security Considerations

- Ensure that IAM roles are configured with the principle of least privilege.
- Lambda execution roles should only have the necessary permissions to assume roles and write to the S3 bucket.
- Sensitive data (like user tags and access key information) should be handled securely.

