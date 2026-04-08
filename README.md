# TrustOS AWS Scanner (Open-Core)

Welcome to the open-source auditing core of **TrustOS**.

As a DevSecOps platform operating at the intersection of AI Remediation and Infrastructure, we take Data Privacy extremely seriously. We have open-sourced the exact AWS scanning logic used by our platform to provide cryptographic proof that **we do not, and cannot, read your Personally Identifiable Information (PII) or Application Data.**

## 🛡️ The Control Plane Guarantee

If you analyze the source code located in `src/lib/scanners/aws`, you will find that TrustOS exclusively interacts with the **AWS Configuration Control Plane**.

* **We scan metadata:** e.g., `s3:GetBucketPublicAccessBlock` or `kms:DescribeKey`.
* **We DO NOT scan data:** There is absolutely zero logic or IAM capability within this engine to execute `s3:GetObject`, `dynamodb:Scan`, or `rds:Select`.

## ⚙️ How it Works

The scanner relies on the enterprise-standard **Cross-Account Role Assumption** architecture.
```typescript
const assumeResponse = await stsClient.send(new AssumeRoleCommand({
  RoleArn: creds.roleArn,
  RoleSessionName: 'TrustOS-Scanner',
  ExternalId: creds.externalId
}));
```

We do not require long-lived static Access Keys to operate in your production environment. By utilizing an AWS `AssumeRole` configured strictly with `ReadOnlyAccess` alongside an `ExternalId` designed to prevent confused-deputy attacks, our engine mathematically guarantees tenant isolation.

## 📝 Policy Rules Excerpt
You can view exactly what vulnerabilities our engine flags by inspecting `src/lib/scanners/aws/policy-rules.ts`.

Some of our default rules include:
- Unencrypted S3 Buckets
- EC2 Security Groups open to `0.0.0.0/0` (SSH/RDP)
- RDS Instances without KMS Customer Managed Keys
- IAM Root Accounts lacking MFA

*TrustOS is an AI-powered active remediation platform spanning AWS, GitHub, and Terraform.*
