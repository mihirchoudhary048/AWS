import boto3
import pandas as pd

# Initialize AWS clients
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
rds = boto3.client('rds')
iam = boto3.client('iam')
lambda_client = boto3.client('lambda')

# =========================
# Collect EC2 Instances
# =========================
ec2_instances = []
response = ec2.describe_instances()
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        launch_time = instance.get('LaunchTime')
        if launch_time:
            launch_time = launch_time.replace(tzinfo=None)  # Remove timezone

        ec2_instances.append([
            instance['InstanceId'],
            instance.get('InstanceType', 'N/A'),
            instance.get('State', {}).get('Name', 'N/A'),
            instance.get('PublicIpAddress', 'N/A'),
            instance.get('PrivateIpAddress', 'N/A'),
            launch_time,
            instance.get('Tags', 'N/A')
        ])

df_ec2 = pd.DataFrame(ec2_instances, columns=["Instance ID", "Type", "State", "Public IP", "Private IP", "Launch Time", "Tags"])

# =========================
# Collect VPCs
# =========================
vpcs = []
vpc_response = ec2.describe_vpcs()
for vpc in vpc_response['Vpcs']:
    vpcs.append([vpc['VpcId'], vpc.get('CidrBlock', 'N/A'), vpc.get('IsDefault', 'N/A')])

df_vpcs = pd.DataFrame(vpcs, columns=["VPC ID", "CIDR Block", "Is Default"])

# =========================
# Collect EBS Volumes
# =========================
ebs_volumes = []
ebs_response = ec2.describe_volumes()
for volume in ebs_response['Volumes']:
    ebs_volumes.append([
        volume['VolumeId'],
        volume.get('Size', 'N/A'),
        volume.get('State', 'N/A'),
        volume.get('VolumeType', 'N/A'),
        volume.get('AvailabilityZone', 'N/A'),
        volume.get('CreateTime').replace(tzinfo=None)  # Remove timezone
    ])

df_ebs = pd.DataFrame(ebs_volumes, columns=["Volume ID", "Size (GB)", "State", "Type", "Availability Zone", "Created Time"])

# =========================
# Collect S3 Buckets
# =========================
s3_buckets = []
response = s3.list_buckets()
for bucket in response['Buckets']:
    creation_date = bucket['CreationDate'].replace(tzinfo=None)  # Remove timezone
    s3_buckets.append([bucket['Name'], creation_date])

df_s3 = pd.DataFrame(s3_buckets, columns=["Bucket Name", "Creation Date"])

# =========================
# Collect RDS Databases
# =========================
rds_instances = []
rds_response = rds.describe_db_instances()
for db in rds_response['DBInstances']:
    rds_instances.append([
        db['DBInstanceIdentifier'],
        db.get('DBInstanceClass', 'N/A'),
        db.get('Engine', 'N/A'),
        db.get('DBInstanceStatus', 'N/A'),
        db.get('Endpoint', {}).get('Address', 'N/A')
    ])

df_rds = pd.DataFrame(rds_instances, columns=["DB Identifier", "DB Class", "Engine", "Status", "Endpoint"])

# =========================
# Collect IAM Users & Roles
# =========================
iam_users = []
users_response = iam.list_users()
for user in users_response['Users']:
    creation_date = user['CreateDate'].replace(tzinfo=None)  # Remove timezone
    iam_users.append([user['UserName'], user['Arn'], creation_date])

df_iam_users = pd.DataFrame(iam_users, columns=["User Name", "User ARN", "Creation Date"])

iam_roles = []
roles_response = iam.list_roles()
for role in roles_response['Roles']:
    creation_date = role['CreateDate'].replace(tzinfo=None)  # Remove timezone
    iam_roles.append([role['RoleName'], role['Arn'], creation_date])

df_iam_roles = pd.DataFrame(iam_roles, columns=["Role Name", "Role ARN", "Creation Date"])

# =========================
# Collect Lambda Functions
# =========================
lambda_functions = []
lambda_response = lambda_client.list_functions()
for function in lambda_response['Functions']:
    lambda_functions.append([
        function['FunctionName'],
        function['Runtime'],
        function['Handler'],
        function['MemorySize'],
        function['Timeout']
    ])

df_lambda = pd.DataFrame(lambda_functions, columns=["Function Name", "Runtime", "Handler", "Memory Size", "Timeout"])

# =========================
# Save to Excel File
# =========================
excel_filename = "aws_inventory_report.xlsx"
with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
    df_ec2.to_excel(writer, sheet_name="EC2 Instances", index=False)
    df_vpcs.to_excel(writer, sheet_name="VPCs", index=False)
    df_ebs.to_excel(writer, sheet_name="EBS Volumes", index=False)
    df_s3.to_excel(writer, sheet_name="S3 Buckets", index=False)
    df_rds.to_excel(writer, sheet_name="RDS Databases", index=False)
    df_iam_users.to_excel(writer, sheet_name="IAM Users", index=False)
    df_iam_roles.to_excel(writer, sheet_name="IAM Roles", index=False)
    df_lambda.to_excel(writer, sheet_name="Lambda Functions", index=False)

print(f"✅ AWS Inventory Report saved as '{excel_filename}'")

# Verify file exists
import os
if os.path.exists(excel_filename):
    print(f"✅ The file '{excel_filename}' is available for download.")
else:
    print("❌ File not found. Something went wrong!")
