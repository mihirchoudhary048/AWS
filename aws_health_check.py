import boto3
import csv
import datetime

# -------------------------
# GLOBAL CONFIG / THRESHOLDS
# -------------------------
CPU_THRESHOLD_EC2 = 80.0  # If CPU > 80% => unhealthy
CPU_THRESHOLD_RDS = 80.0
ERROR_THRESHOLD_LAMBDA = 5  # If there are >5 errors in last X mins => unhealthy
S3_ENCRYPTION_REQUIRED = True
S3_VERSIONING_REQUIRED = True
ELB_5XX_THRESHOLD = 10  # If 5XX errors in last 5 mins > 10 => unhealthy

# Used for CloudWatch metric queries
NOW = datetime.datetime.utcnow()
START_TIME = NOW - datetime.timedelta(minutes=15)  # Last 15 minutes
END_TIME = NOW

# AWS Clients
ec2_client = boto3.client('ec2')
cw_client = boto3.client('cloudwatch')
rds_client = boto3.client('rds')
lambda_client = boto3.client('lambda')
s3_client = boto3.client('s3')
elbv2_client = boto3.client('elbv2')

def check_ec2_advanced():
    """
    Advanced EC2 check with CPU metrics from CloudWatch.
    """
    results = []
    reservations = ec2_client.describe_instances().get('Reservations', [])
    all_instances = [inst for res in reservations for inst in res.get('Instances', [])]

    # If no EC2 found, add placeholder row
    if not all_instances:
        results.append({
            "Service": "EC2",
            "ResourceId": "No EC2 found",
            "Status": "N/A",
            "Note": "No EC2 instances in this account"
        })
        return results

    status_resp = ec2_client.describe_instance_status(IncludeAllInstances=True)
    instance_status_map = {s['InstanceId']: s for s in status_resp.get('InstanceStatuses', [])}

    for instance in all_instances:
        instance_id = instance['InstanceId']
        state = instance['State']['Name']  
        note = f"EC2 state: {state}"
        health_status = "UNKNOWN"

        # Basic instance status
        if instance_id in instance_status_map:
            sys_status = instance_status_map[instance_id]['SystemStatus']['Status']
            inst_status = instance_status_map[instance_id]['InstanceStatus']['Status']
            if sys_status == "ok" and inst_status == "ok" and state == "running":
                health_status = "HEALTHY"
            elif state in ["stopped", "shutting-down", "terminated"]:
                health_status = "OFFLINE"
            else:
                health_status = "UNHEALTHY"
            note += f", System={sys_status}, Instance={inst_status}"
        else:
            health_status = "PENDING" if state == "running" else "OFFLINE"

        # Check CPU usage if running/healthy
        if health_status in ["HEALTHY", "PENDING"]:
            metric_resp = cw_client.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=START_TIME,
                EndTime=END_TIME,
                Period=300,  # 5-min intervals
                Statistics=['Average']
            )
            datapoints = metric_resp.get('Datapoints', [])
            if datapoints:
                avg_cpu = sorted(datapoints, key=lambda x: x['Timestamp'])[-1]['Average']
                note += f", CPU={avg_cpu:.1f}%"
                if avg_cpu > CPU_THRESHOLD_EC2:
                    health_status = "UNHEALTHY"
                    note += f" (exceeds {CPU_THRESHOLD_EC2}%)"
            else:
                note += ", No CPU datapoints"

        results.append({
            "Service": "EC2",
            "ResourceId": instance_id,
            "Status": health_status,
            "Note": note
        })

    return results

def check_rds_advanced():
    """
    Advanced RDS check (availability + CPU).
    """
    results = []
    dbs = rds_client.describe_db_instances().get('DBInstances', [])

    # If no RDS found, add placeholder row
    if not dbs:
        results.append({
            "Service": "RDS",
            "ResourceId": "No RDS found",
            "Status": "N/A",
            "Note": "No RDS instances in this account"
        })
        return results

    for db in dbs:
        db_id = db['DBInstanceIdentifier']
        status = db['DBInstanceStatus']
        health_status = "UNHEALTHY" if status != 'available' else "HEALTHY"
        note = f"RDS status: {status}"

        # Check CPU usage
        metric_resp = cw_client.get_metric_statistics(
            Namespace='AWS/RDS',
            MetricName='CPUUtilization',
            Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
            StartTime=START_TIME,
            EndTime=END_TIME,
            Period=300,
            Statistics=['Average']
        )
        datapoints = metric_resp.get('Datapoints', [])
        if datapoints:
            avg_cpu = sorted(datapoints, key=lambda x: x['Timestamp'])[-1]['Average']
            note += f", CPU={avg_cpu:.1f}%"
            if avg_cpu > CPU_THRESHOLD_RDS and health_status == "HEALTHY":
                health_status = "UNHEALTHY"
                note += f" (exceeds {CPU_THRESHOLD_RDS}%)"

        results.append({
            "Service": "RDS",
            "ResourceId": db_id,
            "Status": health_status,
            "Note": note
        })

    return results

def check_lambda_advanced():
    """
    Checks Lambda state + errors from CloudWatch.
    """
    results = []
    funcs = lambda_client.list_functions().get('Functions', [])

    # If no Lambda found
    if not funcs:
        results.append({
            "Service": "Lambda",
            "ResourceId": "No Lambda found",
            "Status": "N/A",
            "Note": "No Lambda functions in this account"
        })
        return results

    for func in funcs:
        func_name = func['FunctionName']
        config = lambda_client.get_function_configuration(FunctionName=func_name)
        state = config.get('State', 'Unknown')  
        health_status = "HEALTHY" if state == "Active" else "UNHEALTHY"
        note = f"Lambda state: {state}"

        # Check error count
        metric_resp = cw_client.get_metric_statistics(
            Namespace='AWS/Lambda',
            MetricName='Errors',
            Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
            StartTime=START_TIME,
            EndTime=END_TIME,
            Period=300,
            Statistics=['Sum']
        )
        datapoints = metric_resp.get('Datapoints', [])
        if datapoints:
            latest_errors = sorted(datapoints, key=lambda x: x['Timestamp'])[-1]['Sum']
            note += f", Errors={int(latest_errors)}"
            if latest_errors > ERROR_THRESHOLD_LAMBDA:
                health_status = "UNHEALTHY"
                note += f" (exceeds {ERROR_THRESHOLD_LAMBDA})"

        results.append({
            "Service": "Lambda",
            "ResourceId": func_name,
            "Status": health_status,
            "Note": note
        })

    return results

def check_s3_advanced():
    """
    Checks S3 for public ACL + optional encryption/versioning.
    """
    results = []
    resp = s3_client.list_buckets()
    buckets = resp.get('Buckets', [])

    # If no buckets found
    if not buckets:
        results.append({
            "Service": "S3",
            "ResourceId": "No S3 found",
            "Status": "N/A",
            "Note": "No S3 buckets in this account"
        })
        return results

    for b in buckets:
        name = b['Name']
        health_status = "HEALTHY"
        note = ""

        # Check ACL
        try:
            acl_resp = s3_client.get_bucket_acl(Bucket=name)
            grants = acl_resp.get('Grants', [])
            is_public = False
            for g in grants:
                grantee = g.get('Grantee', {})
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    is_public = True
                    break
            if is_public:
                health_status = "UNHEALTHY"
                note += "Public ACL; "
        except Exception as e:
            health_status = "UNHEALTHY"
            note += f"ACL error: {e}; "

        # Check encryption
        if S3_ENCRYPTION_REQUIRED:
            try:
                s3_client.get_bucket_encryption(Bucket=name)
                note += "Encryption: OK; "
            except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                health_status = "UNHEALTHY"
                note += "No encryption; "

        # Check versioning
        if S3_VERSIONING_REQUIRED:
            try:
                ver = s3_client.get_bucket_versioning(Bucket=name)
                status = ver.get('Status', 'None')
                if status != 'Enabled':
                    health_status = "UNHEALTHY"
                    note += f"Versioning: {status}; "
                else:
                    note += "Versioning: Enabled; "
            except Exception as e:
                health_status = "UNHEALTHY"
                note += f"Versioning error: {e}; "

        results.append({
            "Service": "S3",
            "ResourceId": name,
            "Status": health_status,
            "Note": note.strip()
        })

    return results

def check_elb_advanced():
    """
    Checks ALB/NLB for 5XX + target health. 
    Adds placeholder row if no LBs found.
    """
    results = []
    lbs_resp = elbv2_client.describe_load_balancers()
    lbs = lbs_resp.get('LoadBalancers', [])

    # If no load balancers
    if not lbs:
        results.append({
            "Service": "ELBv2",
            "ResourceId": "No LB found",
            "Status": "N/A",
            "Note": "No ALB/NLB in this account"
        })
        return results

    for lb in lbs:
        arn = lb['LoadBalancerArn']
        name = lb['LoadBalancerName']
        lb_type = lb['Type']
        health_status = "HEALTHY"
        note = f"Type={lb_type}"

        # 5XX check
        metric_name = 'HTTPCode_ELB_5XX_Count'
        namespace = 'AWS/ApplicationELB'
        if lb_type == 'network':
            metric_name = 'TCP_ELB_Reset_Count'
            namespace = 'AWS/NetworkELB'

        m_resp = cw_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{'Name': 'LoadBalancer', 'Value': arn.split('loadbalancer/')[-1]}],
            StartTime=START_TIME,
            EndTime=END_TIME,
            Period=300,
            Statistics=['Sum']
        )
        datapoints = m_resp.get('Datapoints', [])
        total_5xx = 0
        if datapoints:
            total_5xx = sum(d['Sum'] for d in datapoints)
            note += f", 5XX={int(total_5xx)}"

        if total_5xx > ELB_5XX_THRESHOLD:
            health_status = "UNHEALTHY"
            note += f" (exceeds {ELB_5XX_THRESHOLD})"

        # Target health
        tgroups_resp = elbv2_client.describe_target_groups(LoadBalancerArn=arn)
        tg_arns = [tg['TargetGroupArn'] for tg in tgroups_resp.get('TargetGroups', [])]
        any_unhealthy_target = False
        for tgarn in tg_arns:
            th_resp = elbv2_client.describe_target_health(TargetGroupArn=tgarn)
            for desc in th_resp.get('TargetHealthDescriptions', []):
                state = desc['TargetHealth']['State']
                if state != 'healthy':
                    any_unhealthy_target = True
        if any_unhealthy_target:
            health_status = "UNHEALTHY"
            note += ", Some targets unhealthy"

        results.append({
            "Service": "ELBv2",
            "ResourceId": name,
            "Status": health_status,
            "Note": note
        })

    return results

def check_cloudwatch_alarms():
    """
    If no alarms => placeholder, if alarms exist => check if any is ALARM => UNHEALTHY
    """
    results = []
    alarms_resp = cw_client.describe_alarms()
    alarms = alarms_resp.get('MetricAlarms', [])

    if not alarms:
        results.append({
            "Service": "CloudWatch",
            "ResourceId": "No Alarms found",
            "Status": "N/A",
            "Note": "No CloudWatch Alarms in this account"
        })
        return results

    alarms_in_alarm = [a['AlarmName'] for a in alarms if a['StateValue'] == 'ALARM']
    if alarms_in_alarm:
        results.append({
            "Service": "CloudWatch",
            "ResourceId": f"{len(alarms_in_alarm)}_alarms_in_ALARM_state",
            "Status": "UNHEALTHY",
            "Note": f"Alarms in ALARM: {alarms_in_alarm}"
        })
    else:
        results.append({
            "Service": "CloudWatch",
            "ResourceId": "All_alarms_OK",
            "Status": "HEALTHY",
            "Note": f"No alarms in ALARM state. Total={len(alarms)}"
        })

    return results

def save_results_to_csv(results, filename='aws_advanced_health_report.csv'):
    headers = ["Service", "ResourceId", "Status", "Note"]
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(results)
    print(f"✅ Advanced Health report saved to {filename}")

def main():
    print("🔍 Checking EC2 with CPU thresholds...")
    ec2_report = check_ec2_advanced()

    print("🔍 Checking RDS with CPU thresholds...")
    rds_report = check_rds_advanced()

    print("🔍 Checking Lambda errors & state...")
    lambda_report = check_lambda_advanced()

    print("🔍 Checking S3 encryption & versioning + public ACL...")
    s3_report = check_s3_advanced()

    print("🔍 Checking ELB 5xx & target health...")
    elb_report = check_elb_advanced()

    print("🔍 Checking CloudWatch alarms...")
    cw_report = check_cloudwatch_alarms()

    combined = ec2_report + rds_report + lambda_report + s3_report + elb_report + cw_report
    save_results_to_csv(combined, 'aws_advanced_health_report.csv')

    print("✅ Advanced AWS Health Check Completed!")

if __name__ == '__main__':
    main()
