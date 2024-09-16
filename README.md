# AWS Lambda Function: Collect IAM User Metadata Across Multiple Accounts

## Overview
This AWS Lambda function collects IAM user metadata across multiple AWS accounts by assuming a role in each child account. The function retrieves various details, including user tags, creation date, access key metadata, console access, and signing certificates. The data is stored in a CSV file and uploaded to an S3 bucket.

## Functionality
1. **Assume Role**: The function assumes a specific IAM role in each child account to get temporary credentials.
2. **Collect User Metadata**: For each IAM user in the child account, the function retrieves:
   - User tags
   - Creation date and age
   - Access keys and their age
   - Last time an access key was used
   - Console access and last sign-in date
   - MFA status
   - Signing certificates
3. **Retry Mechanism**: The function implements exponential backoff retries in case of throttling or rate limit errors.
4. **Output**: All the collected data is saved as a CSV file in an S3 bucket with a timestamped file name.

## AWS Resources Used
- **AWS Lambda**: This function runs in an AWS Lambda environment.
- **S3**: Used for storing the output CSV file.
- **IAM**: Used to assume roles and fetch IAM user details from child accounts.
- **STS**: Used to assume roles across accounts.

## Prerequisites
- **IAM Role Setup**: Ensure that the target child accounts have the required IAM role (`Assume_Role_Child_Account`) with permissions for `sts:AssumeRole`, `iam:ListUsers`, `iam:ListUserTags`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, `iam:GetLoginProfile`, `iam:ListSigningCertificates`, and `iam:ListMFADevices`.
- **Lambda IAM Permissions**: The Lambda function should have the following permissions:
  - `sts:AssumeRole`
  - `s3:PutObject`

## Environment Variables
- **`ORGANIZATION_ID`**: The AWS Organization ID.
- **`ROLE_NAME`**: The name of the IAM role to assume in child accounts.
- **`S3_BUCKET_NAME`**: The name of the S3 bucket where the output CSV will be stored.

## Input
The function assumes roles in the child AWS accounts listed in the `child_account_ids` array. Update this array with the IDs of the accounts you wish to process.

## Output
The function generates a CSV file in the following format:
- **File Name**: `IAM_USER_TAGS_{ORGANIZATION_ID}_combined_{YYYY-MM-DD_HH-MM-SS}.csv`
- **Columns**:
  - `AccountID`: The ID of the child account.
  - `AccountAlias`: The alias of the child account.
  - `UserName`: The IAM user's name.
  - `Tags`: JSON-encoded list of IAM user tags.
  - `CreationDateTime`: The date and time the IAM user was created.
  - `CreationAgeInDays`: The age of the user in days.
  - `Path`: The path to the IAM user.
  - `Groups`: JSON-encoded list of IAM user groups.
  - `MFAEnabled`: Whether MFA is enabled for the user.
  - `LastActivity`: Last activity recorded for the user's access key.
  - `PasswordAge`: Age of the user's password, if available.
  - `ConsoleLastSignIn`: Last time the user signed in to the AWS Management Console, if available.
  - `AccessKeyID`: The active access key ID for the user.
  - `ActiveKeyAge`: Age of the active access key in days.
  - `AccessKeyLastUsed`: The last time the active access key was used.
  - `ARN`: The Amazon Resource Name (ARN) of the IAM user.
  - `ConsoleAccess`: Whether the user has console access.
  - `SigningCerts`: JSON-encoded list of IAM user's signing certificates.

## Error Handling
If an error occurs during the process, the function logs the error and returns an HTTP 500 status with an error message.

### Throttling
If the function encounters throttling (rate limit) errors, it will retry up to 5 times with an exponential backoff.

## Logging
The Lambda function logs important events and errors, including:
- When roles are successfully assumed.
- When data is successfully processed for each user.
- Any errors encountered, including details about failed role assumption or API calls.

## Example Response
After successful execution, the Lambda function returns a 200 HTTP status code and a message indicating which accounts were processed successfully and which failed. The CSV file is uploaded to the specified S3 bucket.

## Dependencies
The Lambda function requires the following Python libraries:
- `boto3`: AWS SDK for Python to interact with STS, IAM, and S3.
- `json`: For encoding and decoding JSON data.
- `csv`: For writing data to CSV format.
- `math`: For handling exponential backoff during retries.
- `time`: For implementing sleep between retries.

## How to Deploy
1. **Create Lambda Function**: In the AWS Management Console, create a new Lambda function using a compatible runtime (e.g., Python 3.x).
2. **Upload Code**: Upload the provided Python code to the Lambda function.
3. **Configure IAM Role**: Ensure that the Lambda function has the appropriate IAM permissions as mentioned in the Prerequisites.
4. **Set Environment Variables**: Add the following environment variables in the Lambda configuration:
   - `ORGANIZATION_ID`
   - `ROLE_NAME`
   - `S3_BUCKET_NAME`
5. **Run the Function**: Test the function by invoking it. The output CSV will be uploaded to the specified S3 bucket.

## License
This project is licensed under the MIT License.

