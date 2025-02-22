import boto3
import pandas as pd

# Initialize S3 client
s3 = boto3.client('s3')

# List all S3 buckets
response = s3.list_buckets()

# Extract bucket names and creation dates
buckets_data = []
for bucket in response['Buckets']:
    buckets_data.append([bucket['Name'], bucket['CreationDate'].strftime("%Y-%m-%d %H:%M:%S")])

# Convert to DataFrame
df = pd.DataFrame(buckets_data, columns=["Bucket Name", "Creation Date"])

# Save to Excel file
excel_filename = "s3_buckets_list.xlsx"
df.to_excel(excel_filename, index=False)

print(f"Excel file '{excel_filename}' has been created successfully!")

# Verify the file exists in AWS CloudShell
import os
if os.path.exists(excel_filename):
    print(f"✅ The file '{excel_filename}' is available for download.")
else:
    print("❌ File not found. Something went wrong!")
