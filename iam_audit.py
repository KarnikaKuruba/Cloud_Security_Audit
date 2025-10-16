#!/usr/bin/env python3
"""Simple IAM audit script.
Requirements: boto3
Run: python iam_audit.py --output ../reports/iam_report.md
"""
import boto3
import argparse
from tabulate import tabulate

def list_users(iam):
    users = iam.list_users().get('Users', [])
    rows = []
    for u in users:
        username = u.get('UserName')
        create_date = u.get('CreateDate')
        rows.append([username, str(create_date)])
    return rows

def check_mfa(iam):
    users = iam.list_users().get('Users', [])
    no_mfa = []
    for u in users:
        username = u.get('UserName')
        mfa = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
        if not mfa:
            no_mfa.append(username)
    return no_mfa

def list_inline_policies(iam):
    users = iam.list_users().get('Users', [])
    permissive = []
    for u in users:
        username = u.get('UserName')
        inline = iam.list_user_policies(UserName=username).get('PolicyNames', [])
        if inline:
            permissive.append((username, inline))
    return permissive

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='../reports/iam_report.md')
    args = parser.parse_args()
    iam = boto3.client('iam')
    users = list_users(iam)
    no_mfa = check_mfa(iam)
    inline = list_inline_policies(iam)
    with open(args.output, 'w') as fh:
        fh.write('# IAM Audit Report\n\n')
        fh.write('## Users\n\n')
        fh.write(tabulate(users, headers=['User', 'Created'], tablefmt='github'))
        fh.write('\n\n')
        fh.write('## Users without MFA\n\n')
        for u in no_mfa:
            fh.write(f'- {u}\n')
        fh.write('\n\n')
        fh.write('## Users with inline policies\n\n')
        for u,p in inline:
            fh.write(f'- {u}: {p}\n')
    print('IAM audit completed. Output:', args.output)

if __name__ == '__main__':
    main()
