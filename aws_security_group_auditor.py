import boto3
import xlsxwriter

def list_security_groups():
    """
    Retrieve all security groups in the AWS account.
    """
    ec2_client = boto3.client('ec2')
    paginator = ec2_client.get_paginator('describe_security_groups')
    security_groups = []
    for page in paginator.paginate():
        security_groups.extend(page['SecurityGroups'])
    return security_groups

def analyze_security_group_rules(security_groups):
    """
    Analyze SG rules for each security group.
    Return:
      - open_rules: list of open-to-world rules
      - sg_summary: summary of each SG with counts
    """
    open_rules = []   # individual open rules (inbound/outbound)
    sg_summary = []   # summary: total inbound/outbound + open rule counts

    for sg in security_groups:
        sg_id   = sg.get('GroupId')
        sg_name = sg.get('GroupName', 'UnnamedSG')
        vpc_id  = sg.get('VpcId', 'N/A')
        desc    = sg.get('Description', 'No Description')

        inbound_count  = len(sg.get('IpPermissions', []))
        outbound_count = len(sg.get('IpPermissionsEgress', []))
        open_count     = 0  # number of open rules in this SG

        # ------------------------------
        # Inbound Rules
        # ------------------------------
        for rule in sg.get('IpPermissions', []):
            ip_protocol = rule.get('IpProtocol')
            from_port   = rule.get('FromPort')
            to_port     = rule.get('ToPort')

            # IPv4
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr in ['0.0.0.0/0']:
                    open_count += 1
                    open_rules.append({
                        'GroupId': sg_id,
                        'GroupName': sg_name,
                        'VpcId': vpc_id,
                        'Direction': 'Inbound',
                        'Protocol': ip_protocol,
                        'PortRange': get_port_range_str(from_port, to_port),
                        'Cidr': cidr,
                    })

            # IPv6
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr_ipv6 = ipv6_range.get('CidrIpv6')
                if cidr_ipv6 in ['::/0']:
                    open_count += 1
                    open_rules.append({
                        'GroupId': sg_id,
                        'GroupName': sg_name,
                        'VpcId': vpc_id,
                        'Direction': 'Inbound',
                        'Protocol': ip_protocol,
                        'PortRange': get_port_range_str(from_port, to_port),
                        'Cidr': cidr_ipv6,
                    })

        # ------------------------------
        # Outbound Rules
        # ------------------------------
        for rule in sg.get('IpPermissionsEgress', []):
            ip_protocol = rule.get('IpProtocol')
            from_port   = rule.get('FromPort')
            to_port     = rule.get('ToPort')

            # IPv4
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr in ['0.0.0.0/0']:
                    open_count += 1
                    open_rules.append({
                        'GroupId': sg_id,
                        'GroupName': sg_name,
                        'VpcId': vpc_id,
                        'Direction': 'Outbound',
                        'Protocol': ip_protocol,
                        'PortRange': get_port_range_str(from_port, to_port),
                        'Cidr': cidr,
                    })

            # IPv6
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr_ipv6 = ipv6_range.get('CidrIpv6')
                if cidr_ipv6 in ['::/0']:
                    open_count += 1
                    open_rules.append({
                        'GroupId': sg_id,
                        'GroupName': sg_name,
                        'VpcId': vpc_id,
                        'Direction': 'Outbound',
                        'Protocol': ip_protocol,
                        'PortRange': get_port_range_str(from_port, to_port),
                        'Cidr': cidr_ipv6,
                    })

        # summarize this SG
        sg_summary.append({
            'GroupId': sg_id,
            'GroupName': sg_name,
            'VpcId': vpc_id,
            'Description': desc,
            'InboundRules': inbound_count,
            'OutboundRules': outbound_count,
            'OpenToWorldRules': open_count
        })

    return open_rules, sg_summary

def get_port_range_str(from_port, to_port):
    """
    Convert port range to a nice string: '22' or '20-21' or 'All'
    -1 often means all ports allowed
    """
    if from_port is None or to_port is None:
        return 'None'
    if from_port == -1 and to_port == -1:
        return 'All'
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"

def save_audit_report_to_excel(open_rules, sg_summary, filename='sg_audit_report.xlsx'):
    """
    Save open_rules and sg_summary to a multi-sheet Excel file.
    """
    workbook = xlsxwriter.Workbook(filename)

    # ---------------------------
    # Sheet 1: OpenToWorld Rules
    # ---------------------------
    sheet_open = workbook.add_worksheet('OpenToWorldRules')
    headers_open = [
        'GroupId', 'GroupName', 'VpcId',
        'Direction', 'Protocol', 'PortRange', 'Cidr'
    ]
    for col_idx, head in enumerate(headers_open):
        sheet_open.write(0, col_idx, head)

    for row_idx, rule in enumerate(open_rules, start=1):
        sheet_open.write(row_idx, 0, rule['GroupId'])
        sheet_open.write(row_idx, 1, rule['GroupName'])
        sheet_open.write(row_idx, 2, rule['VpcId'])
        sheet_open.write(row_idx, 3, rule['Direction'])
        sheet_open.write(row_idx, 4, rule['Protocol'])
        sheet_open.write(row_idx, 5, rule['PortRange'])
        sheet_open.write(row_idx, 6, rule['Cidr'])

    # ---------------------------
    # Sheet 2: SG Overview
    # ---------------------------
    sheet_sg = workbook.add_worksheet('SecurityGroups')
    headers_sg = [
        'GroupId', 'GroupName', 'VpcId', 'Description',
        'InboundRules', 'OutboundRules', 'OpenToWorldRules'
    ]
    for col_idx, head in enumerate(headers_sg):
        sheet_sg.write(0, col_idx, head)

    for row_idx, sg in enumerate(sg_summary, start=1):
        sheet_sg.write(row_idx, 0, sg['GroupId'])
        sheet_sg.write(row_idx, 1, sg['GroupName'])
        sheet_sg.write(row_idx, 2, sg['VpcId'])
        sheet_sg.write(row_idx, 3, sg['Description'])
        sheet_sg.write(row_idx, 4, sg['InboundRules'])
        sheet_sg.write(row_idx, 5, sg['OutboundRules'])
        sheet_sg.write(row_idx, 6, sg['OpenToWorldRules'])

    workbook.close()
    print(f"✅ Audit report saved: {filename}")

def main():
    print("🔎 Retrieving security groups...")
    sgs = list_security_groups()
    print(f"✅ Found {len(sgs)} security groups.")

    print("🔎 Analyzing security group rules...")
    open_rules, sg_summary = analyze_security_group_rules(sgs)
    print(f"✅ Found {len(open_rules)} open-to-world rule(s).")

    # Save to Excel
    save_audit_report_to_excel(open_rules, sg_summary, 'sg_audit_report.xlsx')

    print("✅ Security Group Audit Completed.")

if __name__ == '__main__':
    main()
