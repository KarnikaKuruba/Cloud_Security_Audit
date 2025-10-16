# Cloud Security Audit - AWS (Sample Project)

This is a sample **Cloud Security Audit** project tailored for a resume/GitHub portfolio.
It contains simple, educational scripts to audit common AWS configuration issues for **IAM**, **S3**, and **EC2**.
**WARNING:** These scripts are intended for learning and auditing accounts you own or have explicit permission to test.

## Structure
- `scripts/iam_audit.py` - Checks IAM users, policies, and overly permissive roles.
- `scripts/s3_audit.py` - Checks S3 buckets for public access, ACLs, and encryption.
- `scripts/ec2_audit.py` - Looks for public-facing EC2 instances and insecure security groups.
- `cis_checks.md` - Short checklist mapping to CIS AWS Foundations.
- `report_template.md` - Template for documenting findings and remediation steps.
- `requirements.txt` - Python deps.

## Usage
1. Configure AWS credentials locally (AWS CLI or environment variables).
2. Create a Python virtual environment and install requirements:
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. Run scripts from the `scripts/` folder:
   ```
   python scripts/iam_audit.py --output ../reports/iam_report.md
   python scripts/s3_audit.py --output ../reports/s3_report.md
   python scripts/ec2_audit.py --output ../reports/ec2_report.md
   ```
4. Combine reports into a final audit report using `report_template.md`.

## Notes
- These scripts use the AWS SDK (boto3). Ensure you have appropriate permissions to list resources.
- Do **not** run on accounts you don't own or aren't authorized to audit.
