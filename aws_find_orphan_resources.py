#!/usr/bin/env python3
"""
AWS Orphaned Resources Finder Script
This script scans the current AWS region for potentially orphaned (unused or untagged) resources across various services.
It uses boto3 to list resources and identifies those that are untagged or have no active dependencies.
Outputs a CSV report summarizing the findings. Logging is enabled for troubleshooting and progress information.
"""
import boto3
import csv
import logging
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
# To reduce verbosity from AWS SDK logs, set boto3 and botocore loggers to WARNING level
logging.getLogger('boto3').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)

# Set your desired region here
REGION = 'ap-south-1'  # Mumbai region

# Define all AWS resource types we want to track
AWS_RESOURCE_TYPES = [
    # Compute
    "EC2 Instance",
    "Lambda Function",
    "ECS Cluster",
    "EKS Cluster",
    # Storage
    "EBS Volume",
    "S3 Bucket",
    "EFS File System",
    # Network
    "VPC",
    "Subnet",
    "Network Interface",
    "Route Table",
    "Internet Gateway",
    "NAT Gateway",
    "Elastic IP",
    # Load Balancers
    "ELB (Classic)",
    "ELBv2 (Application)",
    "ELBv2 (Network)",
    # Security
    "Security Group",
    "Network ACL",
    "IAM Role",
    "IAM User",
    "IAM Group",
    # Database
    "RDS Instance",
    "DynamoDB Table",
    "ElastiCache Cluster",
    # DNS
    "Route53 Hosted Zone",
    "Route53 Health Check",
    # Other
    "CloudWatch Log Group",
    "SNS Topic",
    "SQS Queue",
]

# Add cache dictionary
API_CACHE = {}

def cached_api_call(client, method_name, **kwargs):
    """Cache API calls to avoid repeated queries"""
    cache_key = f"{client.__class__.__name__}_{method_name}_{str(kwargs)}"
    if cache_key not in API_CACHE:
        method = getattr(client, method_name)
        API_CACHE[cache_key] = method(**kwargs)
    return API_CACHE[cache_key]

def find_orphaned_resources():
    """
    Scans the current region and identifies orphaned resources across multiple AWS services.
    Returns a dictionary with resource types as keys and lists of orphaned resources as values.
    """
    # Initialize resources_by_type at the start
    resources_by_type = {resource_type: [] for resource_type in AWS_RESOURCE_TYPES}
    
    # Add progress counter
    total_services = len(AWS_RESOURCE_TYPES)
    current_service = 0

    print(f"\n🔍 Starting AWS orphaned resource scan in region {REGION}...")
    logging.info(f"Scanning region {REGION} for orphaned resources...")

    print("\n📊 Checking Compute Resources...")
    # Initialize global IAM client early
    try:
        iam = boto3.client('iam')
    except Exception as e:
        logging.error(f"Could not create IAM client: {e}")
        iam = None

    print("   → Checking EC2 Instances...")
    # Initialize EC2 client for this region
    try:
        ec2 = boto3.client('ec2', region_name=REGION)
    except Exception as e:
        logging.error(f"Could not create EC2 client for region {REGION}: {e}")
        return resources_by_type

    # 1. Gather all network interfaces in the region.
    #    This will be used to determine which Security Groups, Subnets, and VPCs are in use (attached),
    #    and to find any ENIs that are unattached.
    try:
        network_interfaces = cached_api_call(
            ec2, 
            'describe_network_interfaces'
        ).get('NetworkInterfaces', [])
    except ClientError as e:
        logging.error(f"Error fetching network interfaces in {REGION}: {e}")
        network_interfaces = []
    # Sets to track IDs of used resources
    used_sg_ids = set()
    used_subnet_ids = set()
    used_vpc_ids = set()
    for eni in network_interfaces:
        # Collect security group IDs used by this ENI
        if 'Groups' in eni:
            for sg in eni['Groups']:
                if 'GroupId' in sg:
                    used_sg_ids.add(sg['GroupId'])
        # Collect subnet and VPC IDs used by this ENI
        if 'SubnetId' in eni:
            used_subnet_ids.add(eni['SubnetId'])
        if 'VpcId' in eni:
            used_vpc_ids.add(eni['VpcId'])
        # Identify unattached ENIs (no attachment means not in use)
        attachment = eni.get('Attachment')
        if attachment is None:
            reason_list = ["Unattached"]
            if "Network Interface" not in resources_by_type:
                resources_by_type["Network Interface"] = []
            resources_by_type["Network Interface"].append({
                "ResourceType": "Network Interface",
                "Region": REGION,
                "Identifier": eni.get('NetworkInterfaceId'),
                "Name": "",  # ENIs typically have no Name tag
                "OrphanReason": "; ".join(reason_list)
            })

    # 2. EC2 Instances – check for untagged instances and stopped instances
    try:
        reservations = ec2.describe_instances().get('Reservations', [])
    except ClientError as e:
        logging.error(f"Error fetching EC2 instances in {REGION}: {e}")
        reservations = []
    for res in reservations:
        for inst in res.get('Instances', []):
            inst_id = inst.get('InstanceId')
            tags = inst.get('Tags', [])
            state = inst.get('State', {}).get('Name', '')
            reason_list = []
            
            if not tags:  # instance has no tags
                reason_list.append("Untagged")
            if state == 'stopped':
                reason_list.append("Stopped")
                
            if reason_list:
                name_tag = ""
                for tag in tags:
                    if tag.get('Key') == 'Name':
                        name_tag = tag.get('Value')
                if "EC2 Instance" not in resources_by_type:
                    resources_by_type["EC2 Instance"] = []
                resources_by_type["EC2 Instance"].append({
                    "ResourceType": "EC2 Instance",
                    "Region": REGION,
                    "Identifier": inst_id,
                    "Name": name_tag,
                    "OrphanReason": "; ".join(reason_list)
                })
    if "EC2 Instance" in resources_by_type:
        logging.info(f"Found {len(resources_by_type['EC2 Instance'])} orphaned EC2 instances")

    print("   → Checking Lambda Functions...")
    # 3. EBS Volumes – check for unattached or untagged volumes.
    try:
        volumes = ec2.describe_volumes().get('Volumes', [])
    except ClientError as e:
        logging.error(f"Error fetching EBS volumes in {REGION}: {e}")
        volumes = []
    for vol in volumes:
        vol_id = vol.get('VolumeId')
        attachments = vol.get('Attachments', [])
        reason_list = []
        if len(attachments) == 0:  # volume is not attached to any instance
            reason_list.append("Unattached")
        if reason_list:
            if "EBS Volume" not in resources_by_type:
                resources_by_type["EBS Volume"] = []
            resources_by_type["EBS Volume"].append({
                "ResourceType": "EBS Volume",
                "Region": REGION,
                "Identifier": vol_id,
                "Name": "",  # could retrieve Name tag from vol_tags if present
                "OrphanReason": "; ".join(reason_list)
            })

    print("   → Checking ECS Clusters...")
    # 4. Elastic IPs – check for unassociated (not attached) or untagged addresses.
    try:
        addresses = ec2.describe_addresses().get('Addresses', [])
    except ClientError as e:
        logging.error(f"Error fetching Elastic IPs in {REGION}: {e}")
        addresses = []
    for addr in addresses:
        alloc_id = addr.get('AllocationId')
        public_ip = addr.get('PublicIp')
        # Determine if EIP is associated with an instance or network interface
        associated = addr.get('AssociationId') or addr.get('InstanceId')
        reason_list = []
        if not associated:  # no association means the EIP is idle
            reason_list.append("Unassociated")
        if reason_list:
            if "Elastic IP" not in resources_by_type:
                resources_by_type["Elastic IP"] = []
            resources_by_type["Elastic IP"].append({
                "ResourceType": "Elastic IP",
                "Region": REGION,
                "Identifier": alloc_id if alloc_id else public_ip,
                "Name": public_ip,  # use the public IP as a human-readable name
                "OrphanReason": "; ".join(reason_list)
            })

    print("   → Checking EKS Clusters...")
    # 5. Security Groups – check for groups not attached to any ENI (unused) or untagged groups.
    try:
        sec_groups = ec2.describe_security_groups().get('SecurityGroups', [])
    except ClientError as e:
        logging.error(f"Error fetching Security Groups in {REGION}: {e}")
        sec_groups = []
    for sg in sec_groups:
        sg_id = sg.get('GroupId')
        sg_name = sg.get('GroupName', "")
        reason_list = []
        # If this security group ID was not seen in any ENI's attached groups, it's not in use
        if sg_id not in used_sg_ids:
            reason_list.append("Unattached")
        if reason_list:
            if "Security Group" not in resources_by_type:
                resources_by_type["Security Group"] = []
            resources_by_type["Security Group"].append({
                "ResourceType": "Security Group",
                "Region": REGION,
                "Identifier": sg_id,
                "Name": sg_name,  # group name (note: default groups have name "default")
                "OrphanReason": "; ".join(reason_list)
            })

    print("\n💾 Checking Storage Resources...")
    # 6. Subnets – check for subnets with no ENIs (no resources) or untagged subnets.
    try:
        subnets = ec2.describe_subnets().get('Subnets', [])
    except ClientError as e:
        logging.error(f"Error fetching Subnets in {REGION}: {e}")
        subnets = []
    for subnet in subnets:
        subnet_id = subnet.get('SubnetId')
        reason_list = []
        if subnet_id not in used_subnet_ids:
            reason_list.append("Unused")
        if reason_list:
            if "Subnet" not in resources_by_type:
                resources_by_type["Subnet"] = []
            resources_by_type["Subnet"].append({
                "ResourceType": "Subnet",
                "Region": REGION,
                "Identifier": subnet_id,
                "Name": "",  # could include Name tag if present
                "OrphanReason": "; ".join(reason_list)
            })

    # 7. VPCs – check for VPCs with no ENIs (empty VPC) or untagged VPCs.
    try:
        vpcs = ec2.describe_vpcs().get('Vpcs', [])
    except ClientError as e:
        logging.error(f"Error fetching VPCs in {REGION}: {e}")
        vpcs = []
    for vpc in vpcs:
        vpc_id = vpc.get('VpcId')
        is_default = vpc.get('IsDefault', False)
        reason_list = []
        if vpc_id not in used_vpc_ids:
            reason_list.append("Unused")
        if reason_list:
            if "VPC" not in resources_by_type:
                resources_by_type["VPC"] = []
            resources_by_type["VPC"].append({
                "ResourceType": "VPC",
                "Region": REGION,
                "Identifier": vpc_id,
                "Name": "default VPC" if is_default else "",
                "OrphanReason": "; ".join(reason_list)
            })

    print("\n🌐 Checking Network Resources...")
    # 8. Classic Load Balancers (ELBv1) – check for no instances or no tags.
    try:
        elb = boto3.client('elb', region_name=REGION)
        load_balancers = elb.describe_load_balancers().get('LoadBalancerDescriptions', [])
    except ClientError as e:
        # If region does not support ELB or permission issue, skip gracefully
        logging.error(f"Error fetching classic load balancers in {REGION}: {e}")
        load_balancers = []
    for lb in load_balancers:
        lb_name = lb.get('LoadBalancerName')
        instances = lb.get('Instances', [])
        reason_list = []
        if len(instances) == 0:
            reason_list.append("NoInstances")
        if reason_list:
            if "ELB (Classic)" not in resources_by_type:
                resources_by_type["ELB (Classic)"] = []
            resources_by_type["ELB (Classic)"].append({
                "ResourceType": "ELB (Classic)",
                "Region": REGION,
                "Identifier": lb_name,
                "Name": lb_name,
                "OrphanReason": "; ".join(reason_list)
            })

    print("\n⚖️ Checking Load Balancers...")
    # 9. Load Balancers v2 (ALB/NLB) – check for no targets or no tags.
    try:
        elbv2 = boto3.client('elbv2', region_name=REGION)
        elbv2_lbs = elbv2.describe_load_balancers().get('LoadBalancers', [])
    except ClientError as e:
        logging.error(f"Error fetching load balancers (v2) in {REGION}: {e}")
        elbv2_lbs = []
    # Fetch tags for all ALBs/NLBs in this region in batches (API allows up to 20 ARNs per call)
    lb_arns = [lb['LoadBalancerArn'] for lb in elbv2_lbs]
    lb_tags_map = {}  # will map LB ARN to its tag list
    if lb_arns:
        for i in range(0, len(lb_arns), 20):
            try:
                tag_chunk = elbv2.describe_tags(ResourceArns=lb_arns[i:i+20]).get('TagDescriptions', [])
                for tag_desc in tag_chunk:
                    arn = tag_desc['ResourceArn']
                    lb_tags_map[arn] = tag_desc.get('Tags', [])
            except ClientError as e:
                logging.warning(f"Could not fetch tags for some ELBv2 load balancers in {REGION}: {e}")
    # Fetch all target groups in the region to check target health (which tells us if targets are registered)
    try:
        target_groups = elbv2.describe_target_groups().get('TargetGroups', [])
    except ClientError as e:
        logging.error(f"Error fetching target groups in {REGION}: {e}")
        target_groups = []
    # Determine the number of targets in each target group
    tg_targets_count = {}
    for tg in target_groups:
        tg_arn = tg.get('TargetGroupArn')
        try:
            health_desc = elbv2.describe_target_health(TargetGroupArn=tg_arn).get('TargetHealthDescriptions', [])
            tg_targets_count[tg_arn] = len(health_desc)
        except ClientError as e:
            tg_targets_count[tg_arn] = 0
            logging.warning(f"Could not describe target health for TG {tg_arn} in {REGION}: {e}")
    # Evaluate each load balancer for orphan criteria
    for lb in elbv2_lbs:
        lb_arn = lb['LoadBalancerArn']
        lb_name = lb.get('LoadBalancerName', '')
        lb_type = lb.get('Type', '')  # e.g., "application" or "network"
        reason_list = []
        # Find all target groups associated with this load balancer (each TG has a list of LoadBalancerArns)
        related_tgs = [tg for tg in target_groups if lb_arn in tg.get('LoadBalancerArns', [])]
        if related_tgs:
            # If every related target group has zero targets, then the LB has no registered targets
            all_empty = True
            for tg in related_tgs:
                if tg_targets_count.get(tg['TargetGroupArn'], 0) > 0:
                    all_empty = False
                    break
            if all_empty:
                reason_list.append("NoTargets")
        else:
            # No target groups found for this LB (should not happen for ALB/NLB, but just in case)
            reason_list.append("NoTargets")
        if reason_list:
            # Label resource type as ALB/NLB for clarity
            lb_label = "ELBv2 (" + lb_type.capitalize() + ")" if lb_type else "ELBv2"
            if lb_label not in resources_by_type:
                resources_by_type[lb_label] = []
            resources_by_type[lb_label].append({
                "ResourceType": lb_label,
                "Region": REGION,
                "Identifier": lb_name,
                "Name": lb_name,
                "OrphanReason": "; ".join(reason_list)
            })

    print("\n🔒 Checking Security Resources...")
    # 10. RDS Instances – check for stopped or untagged RDS databases.
    try:
        rds = boto3.client('rds', region_name=REGION)
        dbs = rds.describe_db_instances().get('DBInstances', [])
    except ClientError as e:
        logging.error(f"Error fetching RDS instances in {REGION}: {e}")
        dbs = []
    for db in dbs:
        db_id = db.get('DBInstanceIdentifier')
        db_status = db.get('DBInstanceStatus')
        reason_list = []
        if db_status and db_status.lower() == 'stopped':
            reason_list.append("Stopped")
        if reason_list:
            if "RDS Instance" not in resources_by_type:
                resources_by_type["RDS Instance"] = []
            resources_by_type["RDS Instance"].append({
                "ResourceType": "RDS Instance",
                "Region": REGION,
                "Identifier": db_id,
                "Name": db_id,  # using the DB instance identifier as the name
                "OrphanReason": "; ".join(reason_list)
            })

    print("\n🗄️ Checking Database Resources...")
    # 11. Lambda Functions – check for untagged functions (and note if no direct triggers).
    try:
        lamb = boto3.client('lambda', region_name=REGION)
        functions = lamb.list_functions().get('Functions', [])
    except ClientError as e:
        logging.error(f"Error fetching Lambda functions in {REGION}: {e}")
        functions = []
    for func in functions:
        func_name = func.get('FunctionName')
        func_arn = func.get('FunctionArn')
        reason_list = []
        # Optionally check if the function has any event source mappings (direct triggers like SQS, DynamoDB, etc.)
        try:
            mappings = lamb.list_event_source_mappings(FunctionName=func_name).get('EventSourceMappings', [])
            if len(mappings) == 0:
                reason_list.append("NoDirectTrigger")
        except ClientError:
            # If unable to list (e.g., permission issue), skip trigger check
            pass
        if reason_list:
            if "Lambda Function" not in resources_by_type:
                resources_by_type["Lambda Function"] = []
            resources_by_type["Lambda Function"].append({
                "ResourceType": "Lambda Function",
                "Region": REGION,
                "Identifier": func_name,
                "Name": func_name,
                "OrphanReason": "; ".join(reason_list)
            })

    # Add checks for remaining services
    # ECS Clusters
    try:
        ecs = boto3.client('ecs', region_name=REGION)
        clusters = ecs.list_clusters().get('clusterArns', [])
        for cluster_arn in clusters:
            services = ecs.list_services(cluster=cluster_arn).get('serviceArns', [])
            if not services:  # Empty cluster
                cluster_name = cluster_arn.split('/')[-1]
                if "ECS Cluster" not in resources_by_type:
                    resources_by_type["ECS Cluster"] = []
                resources_by_type["ECS Cluster"].append({
                    "ResourceType": "ECS Cluster",
                    "Region": REGION,
                    "Identifier": cluster_arn,
                    "Name": cluster_name,
                    "OrphanReason": "Empty"
                })
    except ClientError as e:
        logging.error(f"Error fetching ECS clusters in {REGION}: {e}")

    # EKS Clusters
    try:
        eks = boto3.client('eks', region_name=REGION)
        clusters = eks.list_clusters().get('clusters', [])
        for cluster_name in clusters:
            cluster = eks.describe_cluster(name=cluster_name).get('cluster', {})
            if cluster.get('status') == 'FAILED':
                if "EKS Cluster" not in resources_by_type:
                    resources_by_type["EKS Cluster"] = []
                resources_by_type["EKS Cluster"].append({
                    "ResourceType": "EKS Cluster",
                    "Region": REGION,
                    "Identifier": cluster_name,
                    "Name": cluster_name,
                    "OrphanReason": "Failed"
                })
    except ClientError as e:
        logging.error(f"Error fetching EKS clusters in {REGION}: {e}")

    # CloudWatch Log Groups
    try:
        logs = boto3.client('logs', region_name=REGION)
        paginator = logs.get_paginator('describe_log_groups')
        for page in paginator.paginate():
            for log_group in page['logGroups']:
                if log_group.get('storedBytes', 0) == 0:  # Empty log group
                    if "CloudWatch Log Group" not in resources_by_type:
                        resources_by_type["CloudWatch Log Group"] = []
                    resources_by_type["CloudWatch Log Group"].append({
                        "ResourceType": "CloudWatch Log Group",
                        "Region": REGION,
                        "Identifier": log_group['logGroupName'],
                        "Name": log_group['logGroupName'],
                        "OrphanReason": "Empty"
                    })
    except ClientError as e:
        logging.error(f"Error fetching CloudWatch log groups in {REGION}: {e}")

    # Add checks for these services after the CloudWatch Log Groups check and before the global services:
    
    # EFS File Systems
    try:
        efs = boto3.client('efs', region_name=REGION)
        file_systems = efs.describe_file_systems().get('FileSystems', [])
        for fs in file_systems:
            fs_id = fs.get('FileSystemId')
            # Check mount targets
            mount_targets = efs.describe_mount_targets(FileSystemId=fs_id).get('MountTargets', [])
            if not mount_targets:
                if "EFS File System" not in resources_by_type:
                    resources_by_type["EFS File System"] = []
                resources_by_type["EFS File System"].append({
                    "ResourceType": "EFS File System",
                    "Region": REGION,
                    "Identifier": fs_id,
                    "Name": fs.get('Name', ''),
                    "OrphanReason": "No Mount Targets"
                })
    except ClientError as e:
        logging.error(f"Error fetching EFS file systems in {REGION}: {e}")

    # DynamoDB Tables
    try:
        dynamodb = boto3.client('dynamodb', region_name=REGION)
        tables = dynamodb.list_tables().get('TableNames', [])
        for table_name in tables:
            table = dynamodb.describe_table(TableName=table_name).get('Table', {})
            item_count = table.get('ItemCount', 0)
            if item_count == 0:
                if "DynamoDB Table" not in resources_by_type:
                    resources_by_type["DynamoDB Table"] = []
                resources_by_type["DynamoDB Table"].append({
                    "ResourceType": "DynamoDB Table",
                    "Region": REGION,
                    "Identifier": table_name,
                    "Name": table_name,
                    "OrphanReason": "Empty Table"
                })
    except ClientError as e:
        logging.error(f"Error fetching DynamoDB tables in {REGION}: {e}")

    # ElastiCache Clusters
    try:
        elasticache = boto3.client('elasticache', region_name=REGION)
        clusters = elasticache.describe_cache_clusters().get('CacheClusters', [])
        for cluster in clusters:
            cluster_id = cluster.get('CacheClusterId')
            status = cluster.get('CacheClusterStatus')
            if status in ['stopped', 'stopping']:
                if "ElastiCache Cluster" not in resources_by_type:
                    resources_by_type["ElastiCache Cluster"] = []
                resources_by_type["ElastiCache Cluster"].append({
                    "ResourceType": "ElastiCache Cluster",
                    "Region": REGION,
                    "Identifier": cluster_id,
                    "Name": cluster_id,
                    "OrphanReason": f"Status: {status}"
                })
    except ClientError as e:
        logging.error(f"Error fetching ElastiCache clusters in {REGION}: {e}")

    # NAT Gateways
    try:
        nat_gateways = ec2.describe_nat_gateways().get('NatGateways', [])
        for nat in nat_gateways:
            nat_id = nat.get('NatGatewayId')
            state = nat.get('State')
            if state in ['failed', 'deleting', 'deleted']:
                if "NAT Gateway" not in resources_by_type:
                    resources_by_type["NAT Gateway"] = []
                resources_by_type["NAT Gateway"].append({
                    "ResourceType": "NAT Gateway",
                    "Region": REGION,
                    "Identifier": nat_id,
                    "Name": "",
                    "OrphanReason": f"State: {state}"
                })
    except ClientError as e:
        logging.error(f"Error fetching NAT Gateways in {REGION}: {e}")

    # SNS Topics
    try:
        sns = boto3.client('sns', region_name=REGION)
        topics = sns.list_topics().get('Topics', [])
        for topic in topics:
            topic_arn = topic.get('TopicArn')
            # Check subscriptions
            subscriptions = sns.list_subscriptions_by_topic(TopicArn=topic_arn).get('Subscriptions', [])
            if not subscriptions:
                if "SNS Topic" not in resources_by_type:
                    resources_by_type["SNS Topic"] = []
                resources_by_type["SNS Topic"].append({
                    "ResourceType": "SNS Topic",
                    "Region": REGION,
                    "Identifier": topic_arn,
                    "Name": topic_arn.split(':')[-1],
                    "OrphanReason": "No Subscriptions"
                })
    except ClientError as e:
        logging.error(f"Error fetching SNS topics in {REGION}: {e}")

    # SQS Queues
    try:
        sqs = boto3.client('sqs', region_name=REGION)
        queues = sqs.list_queues().get('QueueUrls', [])
        for queue_url in queues:
            # Get queue attributes
            attrs = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['ApproximateNumberOfMessages']
            ).get('Attributes', {})
            if int(attrs.get('ApproximateNumberOfMessages', 0)) == 0:
                if "SQS Queue" not in resources_by_type:
                    resources_by_type["SQS Queue"] = []
                resources_by_type["SQS Queue"].append({
                    "ResourceType": "SQS Queue",
                    "Region": REGION,
                    "Identifier": queue_url,
                    "Name": queue_url.split('/')[-1],
                    "OrphanReason": "Empty Queue"
                })
    except ClientError as e:
        logging.error(f"Error fetching SQS queues in {REGION}: {e}")

    # IAM Users and Groups (in the global services section)
    if iam:  # Only process IAM resources if client was successfully created
        try:
            # IAM Users
            users = iam.list_users().get('Users', [])
            for user in users:
                user_name = user.get('UserName')
                # Check if user has logged in recently
                if not user.get('PasswordLastUsed'):
                    if "IAM User" not in resources_by_type:
                        resources_by_type["IAM User"] = []
                    resources_by_type["IAM User"].append({
                        "ResourceType": "IAM User",
                        "Region": "global",
                        "Identifier": user_name,
                        "Name": user_name,
                        "OrphanReason": "Never logged in"
                    })

            # IAM Groups
            groups = iam.list_groups().get('Groups', [])
            for group in groups:
                group_name = group.get('GroupName')
                # Check if group has any users
                group_users = iam.get_group(GroupName=group_name).get('Users', [])
                if not group_users:
                    if "IAM Group" not in resources_by_type:
                        resources_by_type["IAM Group"] = []
                    resources_by_type["IAM Group"].append({
                        "ResourceType": "IAM Group",
                        "Region": "global",
                        "Identifier": group_name,
                        "Name": group_name,
                        "OrphanReason": "No Users"
                    })
        except ClientError as e:
            logging.error(f"Error fetching IAM users/groups: {e}")

    # Route Tables
    try:
        route_tables = ec2.describe_route_tables().get('RouteTables', [])
        for rt in route_tables:
            rt_id = rt.get('RouteTableId')
            associations = rt.get('Associations', [])
            # Check if route table is not the main route table and has no associations
            if not any(assoc.get('Main', False) for assoc in associations) and not any(not assoc.get('Main', False) for assoc in associations):
                if "Route Table" not in resources_by_type:
                    resources_by_type["Route Table"] = []
                resources_by_type["Route Table"].append({
                    "ResourceType": "Route Table",
                    "Region": REGION,
                    "Identifier": rt_id,
                    "Name": "",
                    "OrphanReason": "No Associations"
                })
    except ClientError as e:
        logging.error(f"Error fetching route tables in {REGION}: {e}")

    # Internet Gateways
    try:
        igws = ec2.describe_internet_gateways().get('InternetGateways', [])
        for igw in igws:
            igw_id = igw.get('InternetGatewayId')
            attachments = igw.get('Attachments', [])
            if not attachments:
                if "Internet Gateway" not in resources_by_type:
                    resources_by_type["Internet Gateway"] = []
                resources_by_type["Internet Gateway"].append({
                    "ResourceType": "Internet Gateway",
                    "Region": REGION,
                    "Identifier": igw_id,
                    "Name": "",
                    "OrphanReason": "Not Attached"
                })
    except ClientError as e:
        logging.error(f"Error fetching internet gateways in {REGION}: {e}")

    # Network ACLs
    try:
        nacls = ec2.describe_network_acls().get('NetworkAcls', [])
        for nacl in nacls:
            nacl_id = nacl.get('NetworkAclId')
            associations = nacl.get('Associations', [])
            if not associations:
                if "Network ACL" not in resources_by_type:
                    resources_by_type["Network ACL"] = []
                resources_by_type["Network ACL"].append({
                    "ResourceType": "Network ACL",
                    "Region": REGION,
                    "Identifier": nacl_id,
                    "Name": "",
                    "OrphanReason": "No Associations"
                })
    except ClientError as e:
        logging.error(f"Error fetching network ACLs in {REGION}: {e}")

    # End of per-region loop.

    # 12. Global Services – S3, IAM, Route53 (these are not tied to a specific region).
    logging.info("--- Scanning global services (S3, IAM, Route53) ---")

    # Initialize IAM client
    try:
        iam = boto3.client('iam')
    except ClientError as e:
        logging.error(f"Error creating IAM client: {e}")
        iam = None

    print("\n🌍 Checking Global Services...")
    # S3 Buckets – check for empty or untagged buckets.
    try:
        s3 = boto3.client('s3')
        buckets = s3.list_buckets().get('Buckets', [])
    except ClientError as e:
        logging.error(f"Error listing S3 buckets: {e}")
        buckets = []
    for bucket in buckets:
        bucket_name = bucket.get('Name')
        # Check if bucket is empty by attempting to list at most 1 object
        empty = False
        try:
            obj_list = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            if obj_list.get('KeyCount', 0) == 0:
                empty = True
        except ClientError as e:
            logging.warning(f"Could not list objects for bucket {bucket_name}: {e}")
        reason_list = []
        if empty:
            reason_list.append("Empty")
        if reason_list:
            if "S3 Bucket" not in resources_by_type:
                resources_by_type["S3 Bucket"] = []
            resources_by_type["S3 Bucket"].append({
                "ResourceType": "S3 Bucket",
                "Region": "global",
                "Identifier": bucket_name,
                "Name": bucket_name,
                "OrphanReason": "; ".join(reason_list)
            })

    # IAM Roles – check for untagged roles or roles not associated with any instance profile.
    if iam:  # Only process IAM roles if client was successfully created
        try:
            roles = iam.list_roles().get('Roles', [])
        except ClientError as e:
            logging.error(f"Error listing IAM roles: {e}")
            roles = []
        for role in roles:
            role_name = role.get('RoleName')
            reason_list = []
            # Check if the role is associated with an EC2 instance profile
            try:
                profiles = iam.list_instance_profiles_for_role(RoleName=role_name).get('InstanceProfiles', [])
            except ClientError as e:
                profiles = []
            if len(profiles) == 0:
                reason_list.append("NoInstanceProfile")
            # (Note: Roles could be used by services like Lambda or ECS, which isn't checked here)
            if reason_list:
                if "IAM Role" not in resources_by_type:
                    resources_by_type["IAM Role"] = []
                resources_by_type["IAM Role"].append({
                    "ResourceType": "IAM Role",
                    "Region": "global",
                    "Identifier": role_name,
                    "Name": role_name,
                    "OrphanReason": "; ".join(reason_list)
                })

    # Route53 Hosted Zones – check for untagged zones, private zones with no VPCs, or zones with no record sets.
    # Route53 is global (no region), using us-east-1 endpoint by default for boto3.
    try:
        r53 = boto3.client('route53')
        zones = r53.list_hosted_zones().get('HostedZones', [])
    except ClientError as e:
        logging.error(f"Error listing Route53 hosted zones: {e}")
        zones = []
    zone_ids = []  # will collect zone IDs for later use (health check association scanning)
    for zone in zones:
        zone_id_full = zone.get('Id', '')             # e.g., "/hostedzone/ZONEID"
        zone_id = zone_id_full.split('/')[-1] if zone_id_full else ''
        zone_name = zone.get('Name', '').rstrip('.')  # strip trailing dot for display
        is_private = zone.get('Config', {}).get('PrivateZone', False)
        associated_vpcs = zone.get('VPCs', [])  # list of associated VPCs (if private)
        reason_list = []
        if is_private and len(associated_vpcs) == 0:
            reason_list.append("NoVPC")
        # Check if the zone has any non-default DNS records (aside from SOA/NS)
        record_count = 0
        try:
            records = r53.list_resource_record_sets(HostedZoneId=zone_id, MaxItems="3")
            record_sets = records.get('ResourceRecordSets', [])
            for r in record_sets:
                if r['Type'] not in ('SOA', 'NS'):
                    record_count += 1
                    break  # found a non-SOA/NS record
        except ClientError as e:
            logging.warning(f"Could not list records for zone {zone_name}: {e}")
        if record_count == 0:
            reason_list.append("NoRecords")
        if reason_list:
            if "Route53 Hosted Zone" not in resources_by_type:
                resources_by_type["Route53 Hosted Zone"] = []
            resources_by_type["Route53 Hosted Zone"].append({
                "ResourceType": "Route53 Hosted Zone",
                "Region": "global",
                "Identifier": zone_name,
                "Name": zone_name,
                "OrphanReason": "; ".join(reason_list)
            })
        zone_ids.append(zone_id)
    # Route53 Health Checks – check for health checks not associated with any record.
    try:
        health_checks = r53.list_health_checks().get('HealthChecks', [])
    except ClientError as e:
        logging.error(f"Error listing Route53 health checks: {e}")
        health_checks = []
    # Determine which health check IDs are referenced by any DNS record in any hosted zone
    used_hc_ids = set()
    for zid in zone_ids:
        try:
            paginator = r53.get_paginator('list_resource_record_sets')
            for page in paginator.paginate(HostedZoneId=zid):
                for record in page.get('ResourceRecordSets', []):
                    hc_id = record.get('HealthCheckId')
                    if hc_id:
                        used_hc_ids.add(hc_id)
        except ClientError as e:
            logging.warning(f"Error scanning records in zone {zid} for health checks: {e}")
    for hc in health_checks:
        hc_id = hc.get('Id')
        reason_list = []
        if hc_id not in used_hc_ids:
            reason_list.append("NotAssociated")
        if reason_list:
            if "Route53 Health Check" not in resources_by_type:
                resources_by_type["Route53 Health Check"] = []
            resources_by_type["Route53 Health Check"].append({
                "ResourceType": "Route53 Health Check",
                "Region": "global",
                "Identifier": hc_id,
                "Name": hc_id,
                "OrphanReason": "; ".join(reason_list)
            })

    # Before returning, log the total number of resources found
    total_resources = sum(len(resources) for resources in resources_by_type.values())
    logging.info(f"Total orphaned resources found: {total_resources}")
    print(f"\nFound {total_resources} total orphaned resources")

    for resource_type, resources in resources_by_type.items():
        if resources:  # Only log non-empty resource types
            logging.info(f"{resource_type}: {len(resources)} orphaned resources")
            print(f"- {resource_type}: {len(resources)} resources")

    return resources_by_type

def get_resource_check_description(resource_type):
    """Helper function to get the description of what is checked for each resource type"""
    descriptions = {
        "EC2 Instance": "Checks for: Stopped instances, Untagged instances",
        "EBS Volume": "Checks for: Unattached volumes",
        "S3 Bucket": "Checks for: Empty buckets",
        # ...rest of the descriptions...
    }
    return descriptions.get(resource_type, "Checks for: Orphaned resources")

def write_to_excel(data):
    """
    Writes the orphaned resources data to separate sheets in an Excel file.
    Creates sheets for all resource types, even if no orphaned resources found.
    """
    try:
        import pandas as pd
        from datetime import datetime

        print("\nCreating Excel report...")
        logging.info("Starting Excel report generation")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        excel_file = f"orphaned_resources_report_{timestamp}.xlsx"

        with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:
            workbook = writer.book

            # Create formats
            header_format = workbook.add_format({
                'bold': True,
                'bg_color': '#D3D3D3',
                'border': 1
            })
            
            title_format = workbook.add_format({
                'bold': True,
                'font_size': 14,
                'bg_color': '#4F81BD',
                'font_color': 'white',
                'border': 1
            })

            subtitle_format = workbook.add_format({
                'bold': True,
                'font_size': 12,
                'bg_color': '#B8CCE4',
                'border': 1
            })

            no_data_format = workbook.add_format({
                'italic': True,
                'font_color': '#808080'
            })

            link_format = workbook.add_format({
                'font_color': 'blue',
                'underline': True
            })

            # Create Summary sheet first
            worksheet = workbook.add_worksheet('Summary')
            
            # Write title
            worksheet.merge_range('A1:D1', 'AWS Orphaned Resources Scan Summary', title_format)
            
            # Write scan details
            worksheet.write('A3', 'Scan Details:', subtitle_format)
            worksheet.write('A4', f'Region: {REGION}')
            worksheet.write('A5', f'Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            worksheet.write('A6', f'Total Resource Types Scanned: {len(AWS_RESOURCE_TYPES)}')
            
            # Group resources by category
            resource_categories = {
                'Compute Resources': ['EC2 Instance', 'Lambda Function', 'ECS Cluster', 'EKS Cluster'],
                'Storage Resources': ['EBS Volume', 'S3 Bucket', 'EFS File System'],
                'Network Resources': ['VPC', 'Subnet', 'Network Interface', 'Route Table', 'Internet Gateway', 'NAT Gateway', 'Elastic IP'],
                'Load Balancers': ['ELB (Classic)', 'ELBv2 (Application)', 'ELBv2 (Network)'],
                'Security Resources': ['Security Group', 'Network ACL', 'IAM Role', 'IAM User', 'IAM Group'],
                'Database Resources': ['RDS Instance', 'DynamoDB Table', 'ElastiCache Cluster'],
                'DNS Resources': ['Route53 Hosted Zone', 'Route53 Health Check'],
                'Other Resources': ['CloudWatch Log Group', 'SNS Topic', 'SQS Queue']
            }

            # Write categorized summary
            row = 10
            total_orphaned = 0
            
            for category, resource_types in resource_categories.items():
                worksheet.write(row, 0, category, subtitle_format)
                worksheet.merge_range(row, 0, row, 3, category, subtitle_format)
                row += 1
                
                # Headers for this category
                worksheet.write(row, 0, 'Resource Type', header_format)
                worksheet.write(row, 1, 'Count', header_format)
                worksheet.write(row, 2, 'Status', header_format)
                worksheet.write(row, 3, 'Details', header_format)
                row += 1
                
                for resource_type in resource_types:
                    resources = data.get(resource_type, [])
                    # Ensure resources is a list and remove any None or empty entries
                    resources = [r for r in resources if r]
                    count = len(resources)
                    total_orphaned += count
                    
                    # Create hyperlink to resource sheet
                    sheet_name = resource_type[:31].replace('/', '_').replace('\\', '_')
                    formula = f'=HYPERLINK("#\'{sheet_name}\'!A1","{resource_type}")'
                    
                    worksheet.write_formula(row, 0, formula, link_format)
                    worksheet.write(row, 1, count)
                    worksheet.write(row, 2, 'Found' if count > 0 else 'Not Found')
                    
                    # Add resource-specific details with improved counting logic
                    details = []
                    if count > 0:
                        if resource_type == "EC2 Instance":
                            stopped = sum(1 for r in resources if "Stopped" in r.get("OrphanReason", ""))
                            untagged = sum(1 for r in resources if "Untagged" in r.get("OrphanReason", ""))
                            details.append(f"Stopped: {stopped}, Untagged: {untagged}")
                        elif resource_type == "EBS Volume":
                            unattached = sum(1 for r in resources if "Unattached" in r.get("OrphanReason", ""))
                            details.append(f"Unattached volumes: {unattached}")
                        elif resource_type == "S3 Bucket":
                            empty = sum(1 for r in resources if "Empty" in r.get("OrphanReason", ""))
                            details.append(f"Empty buckets: {empty}")
                        elif resource_type == "Network Interface":
                            unattached = sum(1 for r in resources if "Unattached" in r.get("OrphanReason", ""))
                            details.append(f"Unattached ENIs: {unattached}")
                        elif resource_type == "Elastic IP":
                            unassociated = sum(1 for r in resources if "Unassociated" in r.get("OrphanReason", ""))
                            details.append(f"Unassociated EIPs: {unassociated}")
                        elif resource_type == "Security Group":
                            unattached = sum(1 for r in resources if "Unattached" in r.get("OrphanReason", ""))
                            details.append(f"Unused security groups: {unattached}")
                        elif resource_type == "VPC":
                            unused = sum(1 for r in resources if "Unused" in r.get("OrphanReason", ""))
                            details.append(f"Unused VPCs: {unused}")
                        elif resource_type == "Subnet":
                            unused = sum(1 for r in resources if "Unused" in r.get("OrphanReason", ""))
                            details.append(f"Unused subnets: {unused}")
                        elif resource_type == "Route Table":
                            no_assoc = sum(1 for r in resources if "No Associations" in r.get("OrphanReason", ""))
                            details.append(f"No associations: {no_assoc}")
                        elif resource_type == "Internet Gateway":
                            unattached = sum(1 for r in resources if "Not Attached" in r.get("OrphanReason", ""))
                            details.append(f"Unattached gateways: {unattached}")
                        elif resource_type == "NAT Gateway":
                            failed = sum(1 for r in resources if "failed" in r.get("OrphanReason", "").lower())
                            deleted = sum(1 for r in resources if "deleted" in r.get("OrphanReason", "").lower())
                            details.append(f"Failed: {failed}, Deleted/Deleting: {deleted}")
                        elif resource_type == "Lambda Function":
                            no_trigger = sum(1 for r in resources if "NoDirectTrigger" in r.get("OrphanReason", ""))
                            details.append(f"Functions without triggers: {no_trigger}")
                        elif resource_type == "RDS Instance":
                            stopped = sum(1 for r in resources if "Stopped" in r.get("OrphanReason", ""))
                            details.append(f"Stopped instances: {stopped}")
                        elif resource_type == "DynamoDB Table":
                            empty = sum(1 for r in resources if "Empty" in r.get("OrphanReason", ""))
                            details.append(f"Empty tables: {empty}")
                        elif resource_type == "ElastiCache Cluster":
                            stopped = sum(1 for r in resources if "stopped" in r.get("OrphanReason", "").lower())
                            details.append(f"Stopped clusters: {stopped}")
                        elif resource_type == "ECS Cluster":
                            empty = sum(1 for r in resources if "Empty" in r.get("OrphanReason", ""))
                            details.append(f"Empty clusters: {empty}")
                        elif resource_type == "EKS Cluster":
                            failed = sum(1 for r in resources if "Failed" in r.get("OrphanReason", ""))
                            details.append(f"Failed clusters: {failed}")
                        elif resource_type == "IAM Role":
                            no_profile = sum(1 for r in resources if "NoInstanceProfile" in r.get("OrphanReason", ""))
                            details.append(f"No instance profile: {no_profile}")
                        elif resource_type == "IAM User":
                            never_logged = sum(1 for r in resources if "Never logged in" in r.get("OrphanReason", ""))
                            details.append(f"Never logged in: {never_logged}")
                        elif resource_type == "IAM Group":
                            no_users = sum(1 for r in resources if "No Users" in r.get("OrphanReason", ""))
                            details.append(f"Empty groups: {no_users}")
                        elif resource_type == "CloudWatch Log Group":
                            empty = sum(1 for r in resources if "Empty" in r.get("OrphanReason", ""))
                            details.append(f"Empty log groups: {empty}")
                        elif resource_type == "SNS Topic":
                            no_subs = sum(1 for r in resources if "No Subscriptions" in r.get("OrphanReason", ""))
                            details.append(f"No subscriptions: {no_subs}")
                        elif resource_type == "SQS Queue":
                            empty = sum(1 for r in resources if "Empty" in r.get("OrphanReason", ""))
                            details.append(f"Empty queues: {empty}")
                        elif resource_type == "Route53 Hosted Zone":
                            no_records = sum(1 for r in resources if "NoRecords" in r.get("OrphanReason", ""))
                            no_vpc = sum(1 for r in resources if "NoVPC" in r.get("OrphanReason", ""))
                            details.append(f"No records: {no_records}, No VPC: {no_vpc}")
                        elif resource_type == "Route53 Health Check":
                            not_associated = sum(1 for r in resources if "NotAssociated" in r.get("OrphanReason", ""))
                            details.append(f"Not associated: {not_associated}")
                    else:
                        # Add descriptive text for resources with no findings
                        details.append(get_resource_check_description(resource_type))

                    worksheet.write(row, 3, '; '.join(details) if details else '')
                    row += 1
                
                row += 1  # Add space between categories

            # Write total at the bottom for Summary sheet
            worksheet.write(row + 1, 0, 'Total Orphaned Resources:', subtitle_format)
            worksheet.write(row + 1, 1, total_orphaned, subtitle_format)
            
            # Set column widths for summary sheet
            worksheet.set_column('A:A', 35)
            worksheet.set_column('B:B', 15)
            worksheet.set_column('C:C', 20)
            worksheet.set_column('D:D', 50)

            # Create individual resource sheets for each AWS resource type
            for resource_type in AWS_RESOURCE_TYPES:
                sheet_name = resource_type[:31].replace('/', '_').replace('\\', '_')
                resources = data.get(resource_type, [])
                import pandas as pd
                if resources:
                    df = pd.DataFrame(resources).fillna("")
                else:
                    df = pd.DataFrame(columns=['ResourceType', 'Region', 'Identifier', 'Name', 'OrphanReason'])
                # Write data to the new sheet starting from row 1 (leaving row 0 for return link)
                df.to_excel(writer, sheet_name=sheet_name, index=False, startrow=1)
                ws = writer.sheets[sheet_name]
                ws.write_url('A1', "internal:'Summary'!A1", link_format, string='← Return to Summary')
                for col_num, value in enumerate(df.columns.values):
                    ws.write(1, col_num, value, header_format)
                ws.set_column('A:A', 15)
                ws.set_column('B:B', 12)
                ws.set_column('C:C', 40)
                ws.set_column('D:D', 30)
                ws.set_column('E:E', 50)

        print(f"\n✅ Report generated successfully: {excel_file}")
        logging.info(f"Excel report generated: {excel_file}")

    except ImportError:
        logging.error("pandas and xlsxwriter are required. Install them using: pip install pandas xlsxwriter")
        print("\n⚠️ Error: Required packages missing. Please install pandas and xlsxwriter.")
    except Exception as e:
        logging.error(f"Failed to write Excel report: {e}")
        print(f"\n⚠️ Error generating Excel report: {str(e)}")
        raise

# ...rest of the existing code...

def main():
    print("\n🚀 Starting AWS Orphaned Resources Scanner...")
    print("===========================================")
    
    # Find orphaned resources
    data = find_orphaned_resources()
    
    # Add debug logging
    print("\nResource scan results:")
    for resource_type, resources in data.items():
        if resources:  # Only show non-empty resource types
            print(f"- {resource_type}: {len(resources)} orphaned resources")
    
    print("\n📝 Generating Excel report...")
    write_to_excel(data)

    print("\n🏁 Scan completed!")

if __name__ == "__main__":
    main()
