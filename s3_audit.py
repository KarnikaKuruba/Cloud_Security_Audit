#!/usr/bin/env python3
"""Simple S3 audit script.
Checks for public ACLs, bucket ACL public grants, and SSE encryption.
"""
import boto3
import argparse
from botocore.exceptions import ClientError

def check_bucket_public(s3, bucket):
    public = False
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            uri = grantee.get('URI', '')
            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                public = True
    except ClientError:
        pass
    return public

def check_encryption(s3, bucket):
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)
        return True
    except ClientError:
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='../reports/s3_report.md')
    args = parser.parse_args()
    s3 = boto3.client('s3')
    buckets = [b['Name'] for b in s3.list_buckets().get('Buckets', [])]
    with open(args.output, 'w') as fh:
        fh.write('# S3 Audit Report\n\n')
        for b in buckets:
            public = check_bucket_public(s3, b)
            enc = check_encryption(s3, b)
            fh.write(f'## Bucket: {b}\n')
            fh.write(f'- Public ACL: {public}\n')
            fh.write(f'- Encryption enabled: {enc}\n\n')
    print('S3 audit completed. Output:', args.output)

if __name__ == '__main__':
    main()
