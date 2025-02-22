import boto3
import pandas as pd

# Initialize AWS clients
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
rds = boto3.client('rds')
iam = boto3.client('iam')
lambda_client = boto3.client('lambda')
route53 = boto3.client('route53')
cloudfront = boto3.client('cloudfront')
ce = boto3.client('ce')  # Cost Explorer

print("🔄 Starting AWS inventory collection...")

# =========================
# Collect EC2 Instances
# =========================
print("\n📊 Collecting EC2 instance data...")
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
print(f"✅ Found {len(ec2_instances)} EC2 instances")

# =========================
# Collect VPCs
# =========================
print("\n📊 Collecting VPC data...")
vpcs = []
vpc_response = ec2.describe_vpcs()
for vpc in vpc_response['Vpcs']:
    vpcs.append([vpc['VpcId'], vpc.get('CidrBlock', 'N/A'), vpc.get('IsDefault', 'N/A')])

df_vpcs = pd.DataFrame(vpcs, columns=["VPC ID", "CIDR Block", "Is Default"])
print(f"✅ Found {len(vpcs)} VPCs")

# =========================
# Collect EBS Volumes
# =========================
print("\n📊 Collecting EBS volume data...")
ebs_volumes = []
ebs_response = ec2.describe_volumes()
for volume in ebs_response['Volumes']:
    ebs_volumes.append([
        volume['VolumeId'],
        volume.get('Size', 'N/A'),
        volume.get('State', 'N/A'),
        volume.get('VolumeType', 'N/A'),
        volume.get('AvailabilityZone', 'N/A'),
        volume.get('CreateTime').replace(tzinfo=None)
    ])

df_ebs = pd.DataFrame(ebs_volumes, columns=["Volume ID", "Size (GB)", "State", "Type", "Availability Zone", "Created Time"])
print(f"✅ Found {len(ebs_volumes)} EBS volumes")

# =========================
# Collect S3 Buckets
# =========================
print("\n📊 Collecting S3 bucket data...")
s3_buckets = []
response = s3.list_buckets()
for bucket in response['Buckets']:
    creation_date = bucket['CreationDate'].replace(tzinfo=None)
    s3_buckets.append([bucket['Name'], creation_date])

df_s3 = pd.DataFrame(s3_buckets, columns=["Bucket Name", "Creation Date"])
print(f"✅ Found {len(s3_buckets)} S3 buckets")

# =========================
# Collect RDS Databases
# =========================
print("\n📊 Collecting RDS database data...")
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
print(f"✅ Found {len(rds_instances)} RDS instances")

# =========================
# Collect IAM Users & Roles
# =========================
print("\n📊 Collecting IAM user data...")
iam_users = []
users_response = iam.list_users()
for user in users_response['Users']:
    creation_date = user['CreateDate'].replace(tzinfo=None)
    iam_users.append([user['UserName'], user['Arn'], creation_date])

df_iam_users = pd.DataFrame(iam_users, columns=["User Name", "User ARN", "Creation Date"])
print(f"✅ Found {len(iam_users)} IAM users")

print("\n📊 Collecting IAM role data...")
iam_roles = []
roles_response = iam.list_roles()
for role in roles_response['Roles']:
    creation_date = role['CreateDate'].replace(tzinfo=None)
    iam_roles.append([role['RoleName'], role['Arn'], creation_date])

df_iam_roles = pd.DataFrame(iam_roles, columns=["Role Name", "Role ARN", "Creation Date"])
print(f"✅ Found {len(iam_roles)} IAM roles")

# =========================
# Collect Lambda Functions
# =========================
print("\n📊 Collecting Lambda function data...")
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
print(f"✅ Found {len(lambda_functions)} Lambda functions")

# =========================
# Collect Route 53 Hosted Zones & Records
# =========================
print("\n📊 Collecting Route 53 data...")
hosted_zones = []
route53_response = route53.list_hosted_zones()
for zone in route53_response['HostedZones']:
    hosted_zones.append([zone['Id'], zone['Name'], zone['ResourceRecordSetCount']])

df_route53 = pd.DataFrame(hosted_zones, columns=["Zone ID", "Domain Name", "Record Count"])
print(f"✅ Found {len(hosted_zones)} hosted zones")

# =========================
# Collect CloudFront Distributions
# =========================
print("\n📊 Collecting CloudFront distribution data...")
cloudfront_distributions = []
cloudfront_response = cloudfront.list_distributions()
if "DistributionList" in cloudfront_response and "Items" in cloudfront_response["DistributionList"]:
    for distribution in cloudfront_response["DistributionList"]["Items"]:
        cloudfront_distributions.append([distribution["Id"], distribution["DomainName"], distribution["Status"]])

df_cloudfront = pd.DataFrame(cloudfront_distributions, columns=["Distribution ID", "Domain Name", "Status"])
print(f"✅ Found {len(cloudfront_distributions)} CloudFront distributions")

# =========================
# Collect AWS Monthly Cost Breakdown
# =========================
print("\n📊 Collecting cost data...")
costs = []
cost_response = ce.get_cost_and_usage(
    TimePeriod={"Start": "2024-02-01", "End": "2024-02-28"},
    Granularity="MONTHLY",
    Metrics=["BlendedCost"]
)

for result in cost_response["ResultsByTime"]:
    costs.append([result["TimePeriod"]["Start"], result["Total"]["BlendedCost"]["Amount"], result["Total"]["BlendedCost"]["Unit"]])

df_cost = pd.DataFrame(costs, columns=["Billing Month", "Cost", "Currency"])
print("✅ Cost data collected successfully")

# =========================
# Save to Excel File
# =========================
print("\n💾 Saving data to Excel file...")
excel_filename = "aws_inventory_advance_report.xlsx"
with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
    df_ec2.to_excel(writer, sheet_name="EC2 Instances", index=False)
    df_vpcs.to_excel(writer, sheet_name="VPCs", index=False)
    df_ebs.to_excel(writer, sheet_name="EBS Volumes", index=False)
    df_s3.to_excel(writer, sheet_name="S3 Buckets", index=False)
    df_rds.to_excel(writer, sheet_name="RDS Databases", index=False)
    df_iam_users.to_excel(writer, sheet_name="IAM Users", index=False)
    df_iam_roles.to_excel(writer, sheet_name="IAM Roles", index=False)
    df_lambda.to_excel(writer, sheet_name="Lambda Functions", index=False)
    df_route53.to_excel(writer, sheet_name="Route 53", index=False)
    df_cloudfront.to_excel(writer, sheet_name="CloudFront", index=False)
    df_cost.to_excel(writer, sheet_name="AWS Cost Report", index=False)

print(f"\n🎉 AWS Inventory Report completed!")
print(f"📁 Report saved as: {excel_filename}")

# Verify file exists
import os
if os.path.exists(excel_filename):
    print(f"✅ The file is ready for download")
else:
    print("❌ Error: File not found!")
