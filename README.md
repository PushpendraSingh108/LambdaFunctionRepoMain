# AWS Lambda Function - EC2 and Account Metadata Merge

## Overview

This AWS Lambda function merges EC2 metadata from a CSV file with account metadata from an Excel file. The function reads data from two S3 buckets, performs a left join operation to merge the files based on account names, and uploads the merged data back to another S3 bucket as an Excel file.

## Functionality

- Loads a CSV file (`Concatenate_EC2_ListAllAccounts.csv`) from an S3 bucket (`dailyec2-bucket`).
- Loads an Excel file (`Accounts_Master.xlsx`) from another S3 bucket (`accounts-master-bucket`).
- Merges both datasets using the "Account Name" column from the CSV and the "Precisely Account Name" column from the Excel file.
- The merged data is saved as an Excel file and uploaded to a third S3 bucket (`dailyec2-metadata-bucket`), with a timestamped file name.

## S3 Buckets Involved

- **Source Bucket 1 (`dailyec2-bucket`)**: Contains the CSV file with EC2 metadata.
- **Source Bucket 2 (`accounts-master-bucket`)**: Contains the Excel file with account metadata.
- **Destination Bucket (`dailyec2-metadata-bucket`)**: The merged output Excel file is uploaded here.

## Prerequisites

- Proper IAM permissions for Lambda to access S3 buckets.
- Ensure the `boto3`, `pandas`, and `openpyxl` libraries are available in the Lambda environment.

## Files Involved

- **CSV File** (`Concatenate_EC2_ListAllAccounts.csv`): Contains EC2 account data.
- **Excel File** (`Accounts_Master.xlsx`): Contains account metadata, which is filtered to include only the necessary columns.

## Dependencies

- **boto3**: AWS SDK for Python to interact with S3.
- **pandas**: Used for data manipulation and merging.
- **openpyxl**: Required to read/write Excel files.

## How It Works

1. **File Loading**: 
   - The CSV and Excel files are loaded from their respective S3 buckets.
   - Data from the CSV file is read into a Pandas DataFrame (`df1`).
   - Data from the Excel file is read into another Pandas DataFrame (`df2`), with only selected columns retained.

2. **Data Merging**:
   - A left join is performed on the "Account Name" from the CSV and "Precisely Account Name" from the Excel file.
   - The merged DataFrame contains EC2 account information, alongside the account metadata.

3. **Saving and Uploading**:
   - The merged DataFrame is written to an Excel file.
   - The file is uploaded to the `dailyec2-metadata-bucket` S3 bucket with a timestamped name.

## Environment Variables

- `BUCKET1_NAME`: Name of the S3 bucket containing the CSV file.
- `BUCKET2_NAME`: Name of the S3 bucket containing the Excel file.
- `BUCKET3_NAME`: Name of the S3 bucket where the merged output will be stored.
- `FILE1_NAME`: Path of the CSV file inside `BUCKET1_NAME`.
- `FILE2_NAME`: Path of the Excel file inside `BUCKET2_NAME`.
- `S3_REGION`: AWS region where the S3 buckets are located.

## Error Handling

- Logs errors using Python's logging module.
- If an error occurs, the function returns a 500 status code with an error message.

## Logging

- Logging is configured using the `logging` module and provides information about:
  - S3 buckets being checked.
  - Shape and samples of data loaded into Pandas DataFrames.
  - Successful completion of the merging process.

## Example Output

The output file will be named something like `Metadata_All_EC2_File_YYYY-MM-DD_HH-MM-SS.xlsx` and will be stored in the destination S3 bucket (`dailyec2-metadata-bucket`).
