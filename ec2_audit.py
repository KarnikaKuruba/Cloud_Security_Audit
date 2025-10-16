#!/usr/bin/env python3
"""Simple EC2 audit script.
Checks for public EC2 instances with public IPs and insecure security group rules (0.0.0.0/0 for SSH/RDP).
"""
import boto3
import argparse

def find_public_instances(ec2):
    instances = ec2.describe_instances(
        Filters=[{'Name':'instance-state-name','Values':['running','stopped']}]
    ).get('Reservations', [])
    public = []
    for r in instances:
        for i in r.get('Instances', []):
            inst_id = i.get('InstanceId')
            public_ip = i.get('PublicIpAddress')
            sg_ids = [sg['GroupId'] for sg in i.get('SecurityGroups', [])]
            if public_ip:
                public.append((inst_id, public_ip, sg_ids))
    return public

def check_sg_rules(ec2, sg_id):
    sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
    issues = []
    for perm in sg.get('IpPermissions', []):
        for ip_range in perm.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            from_port = perm.get('FromPort')
            to_port = perm.get('ToPort')
            if cidr == '0.0.0.0/0' and (from_port in (22,3389) or to_port in (22,3389) or from_port is None):
                issues.append((sg_id, cidr, from_port, to_port))
    return issues

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='../reports/ec2_report.md')
    args = parser.parse_args()
    ec2 = boto3.client('ec2')
    public = find_public_instances(ec2)
    with open(args.output, 'w') as fh:
        fh.write('# EC2 Audit Report\n\n')
        fh.write('## Instances with Public IPs\n\n')
        for inst_id, ip, sgs in public:
            fh.write(f'- Instance: {inst_id}, Public IP: {ip}, Security Groups: {sgs}\n')
            for sg in sgs:
                issues = check_sg_rules(ec2, sg)
                for it in issues:
                    fh.write(f'  - Insecure SG rule: {it}\n')
    print('EC2 audit completed. Output:', args.output)

if __name__ == '__main__':
    main()
