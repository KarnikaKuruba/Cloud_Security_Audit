# CIS AWS Foundations - Short Mapping

- IAM: Ensure MFA on root, avoid use of root, no unused IAM access keys, attach least privilege policies.
- S3: Ensure S3 buckets are not publicly accessible, enforce encryption at rest (SSE), block public ACLs.
- EC2: Restrict security group ingress, avoid 0.0.0.0/0 for SSH/RDP, ensure instances use latest AMIs and have monitoring enabled.
