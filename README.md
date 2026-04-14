# TrustOS — Open-Core AWS Scanner

This repository contains the open-source auditing engine that powers [TrustOS](https://trust-os-sigma.vercel.app). It is published to provide full transparency into the exact scanning logic executed against your AWS infrastructure.

By reading this source, you can verify a critical guarantee: **TrustOS interacts exclusively with the AWS Configuration Control Plane. It does not — and cannot — read your application data, objects, or PII.**

---

## Table of Contents

- [Architecture](#architecture)
- [Data Privacy Guarantee](#data-privacy-guarantee)
- [IAM Permissions (Least Privilege)](#iam-permissions-least-privilege)
  - [Complete Permission Inventory](#complete-permission-inventory)
  - [Custom IAM Policy](#custom-iam-policy)
  - [Setting Up the IAM Role](#setting-up-the-iam-role)
- [What We Scan](#what-we-scan)
- [What We Do Not Scan](#what-we-do-not-scan)
- [Authentication Model](#authentication-model)
- [Policy Rules](#policy-rules)
- [Using TrustOS](#using-trustos)
  - [Connecting AWS](#connecting-aws)
  - [Linking GitHub](#linking-github)
  - [Running Scans](#running-scans)
  - [Automated Remediation](#automated-remediation)
  - [Compliance Monitoring](#compliance-monitoring)
- [Project Structure](#project-structure)
- [License](#license)

---

## Architecture

TrustOS is structured as an open-core platform. This repository contains the scanning engine itself — the component responsible for querying AWS service metadata and evaluating it against a defined set of policy rules. The proprietary components (AI-driven remediation, dashboard, and compliance mapping) are not included here.

The scanner operates through the standard AWS Cross-Account Role Assumption pattern:

```typescript
const assumeResponse = await stsClient.send(new AssumeRoleCommand({
  RoleArn: creds.roleArn,
  RoleSessionName: 'TrustOS-Scanner',
  ExternalId: creds.externalId,
}));
```

No long-lived static credentials are required in production environments. The `ExternalId` parameter prevents confused-deputy attacks and enforces tenant isolation at the IAM layer.

---

## Data Privacy Guarantee

TrustOS follows the principle of **configuration-only access**. The scanner reads how your infrastructure is configured, never what it contains.

**TrustOS WILL access:**
- Bucket-level settings (is encryption on? is public access blocked?)
- Security group rules (which ports are open to which CIDRs?)
- IAM user metadata (is MFA enabled? when was the access key last used?)
- Database instance configuration (is it publicly accessible? is encryption enabled?)
- CloudTrail trail settings (is logging active? is log validation enabled?)
- KMS key rotation status

**TrustOS will NEVER access:**
- ❌ S3 objects — no `s3:GetObject` or `s3:ListBucket` (listing files inside buckets)
- ❌ Database contents — no `rds:DownloadDBLogFilePortion`, no connection to databases
- ❌ DynamoDB items — no `dynamodb:GetItem`, `dynamodb:Scan`, or `dynamodb:Query`
- ❌ Queue messages — no `sqs:ReceiveMessage` or `sns:Subscribe`
- ❌ Secrets — no `secretsmanager:GetSecretValue` or `ssm:GetParameter`
- ❌ CloudWatch logs — no `logs:GetLogEvents` or `logs:FilterLogEvents`
- ❌ Lambda code/env vars — no `lambda:GetFunction` (which can expose environment secrets)
- ❌ Kinesis streams — no `kinesis:GetRecords`

You can verify this by searching the codebase — no import or call to any of these actions exists. The permissions file at `src/lib/scanners/aws/required-permissions.ts` enumerates every single action with its justification.

---

## IAM Permissions (Least Privilege)

> **⚠️ Do NOT use the `ReadOnlyAccess` or `ViewOnlyAccess` managed policies.**
>
> `ReadOnlyAccess` grants ~2,800+ read actions across ALL AWS services — including data-plane actions like `s3:GetObject` (read files), `dynamodb:GetItem` (read database records), `secretsmanager:GetSecretValue` (read secrets), and more.
>
> `ViewOnlyAccess` is slightly narrower but still includes data-access actions and spans services TrustOS doesn't even scan.
>
> TrustOS requires **exactly 22 IAM actions** across 6 services. Use the custom policy below.

### Complete Permission Inventory

Every AWS API call TrustOS makes, why it needs it, and what scanner module uses it:

#### S3 — Bucket Configuration (6 actions)

| IAM Action | SDK Command | What It Detects |
|:-----------|:------------|:----------------|
| `s3:ListAllMyBuckets` | `ListBucketsCommand` | Enumerates buckets for scanning |
| `s3:GetBucketPublicAccessBlock` | `GetPublicAccessBlockCommand` | Public access block misconfiguration |
| `s3:GetEncryptionConfiguration` | `GetBucketEncryptionCommand` | Missing server-side encryption |
| `s3:GetBucketVersioning` | `GetBucketVersioningCommand` | Disabled versioning (data loss risk) |
| `s3:GetBucketLogging` | `GetBucketLoggingCommand` | Missing access logging (audit gap) |
| `s3:GetBucketTagging` | `GetBucketTaggingCommand` | Resource tags for inventory |

#### IAM — User & Policy Configuration (5 actions)

| IAM Action | SDK Command | What It Detects |
|:-----------|:------------|:----------------|
| `iam:ListUsers` | `ListUsersCommand` | Enumerates users for auditing |
| `iam:ListMFADevices` | `ListMFADevicesCommand` | Missing MFA on user accounts |
| `iam:ListAccessKeys` | `ListAccessKeysCommand` | Access key existence |
| `iam:GetAccessKeyLastUsed` | `GetAccessKeyLastUsedCommand` | Stale/unused keys (90+ days) |
| `iam:ListAttachedUserPolicies` | `ListAttachedUserPoliciesCommand` | Overly permissive policies (e.g., AdministratorAccess) |

#### EC2 — Network & Volume Configuration (3 actions)

| IAM Action | SDK Command | What It Detects |
|:-----------|:------------|:----------------|
| `ec2:DescribeSecurityGroups` | `DescribeSecurityGroupsCommand` | Open ports to internet (0.0.0.0/0 on SSH, RDP, DB ports) |
| `ec2:DescribeVolumes` | `DescribeVolumesCommand` | Unencrypted EBS volumes |
| `ec2:DescribeInstances` | `DescribeInstancesCommand` | Instance network exposure (public IPs, security groups) |

#### RDS — Database Configuration (1 action)

| IAM Action | SDK Command | What It Detects |
|:-----------|:------------|:----------------|
| `rds:DescribeDBInstances` | `DescribeDBInstancesCommand` | Public access, missing encryption, short backup retention |

#### CloudTrail — Audit Logging (2 actions)

| IAM Action | SDK Command | What It Detects |
|:-----------|:------------|:----------------|
| `cloudtrail:DescribeTrails` | `DescribeTrailsCommand` | Missing/misconfigured audit trails |
| `cloudtrail:GetTrailStatus` | `GetTrailStatusCommand` | Inactive logging |

#### KMS — Key Management (3 actions)

| IAM Action | SDK Command | What It Detects |
|:-----------|:------------|:----------------|
| `kms:ListKeys` | `ListKeysCommand` | Enumerates keys for rotation audit |
| `kms:DescribeKey` | `DescribeKeyCommand` | Key metadata (filters AWS-managed keys) |
| `kms:GetKeyRotationStatus` | `GetKeyRotationStatusCommand` | Disabled automatic key rotation |

### Custom IAM Policy

Use this policy instead of any AWS managed policy. It contains **exactly 22 actions** — the minimum required for full misconfiguration detection.

The policy is also available as a JSON file: [`TrustOSScannerPolicy.json`](./TrustOSScannerPolicy.json)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustOSS3ConfigAudit",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TrustOSIAMConfigAudit",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TrustOSEC2ConfigAudit",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TrustOSRDSConfigAudit",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TrustOSCloudTrailConfigAudit",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TrustOSKMSConfigAudit",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Why `Resource: "*"`?** Most Describe/List/Get-config actions don't support resource-level restrictions. Additionally, TrustOS must scan ALL resources to detect misconfigurations — scoping to specific ARNs would create blind spots. Every action listed is a configuration metadata read; none can access user data.

### Setting Up the IAM Role

#### Option A: AWS Console (Manual)

1. Go to **IAM → Policies → Create Policy**
2. Select **JSON** tab and paste the policy above
3. Name it `TrustOSScannerPolicy`
4. Go to **IAM → Roles → Create Role**
5. Select **Another AWS Account** and enter the TrustOS account ID
6. Attach the `TrustOSScannerPolicy` you just created
7. Set an **External ID** (TrustOS will provide this during onboarding)
8. Copy the **Role ARN** and provide it to TrustOS

#### Option B: Terraform

```hcl
# TrustOS Scanner - Least Privilege IAM Policy
resource "aws_iam_policy" "trustos_scanner" {
  name        = "TrustOSScannerPolicy"
  description = "Least-privilege policy for TrustOS configuration scanner. Grants exactly 22 read-only config actions across 6 services. No data-plane access."

  policy = file("${path.module}/TrustOSScannerPolicy.json")
}

# Cross-Account Role for TrustOS
resource "aws_iam_role" "trustos_scanner" {
  name = "TrustOSScannerRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::TRUSTOS_ACCOUNT_ID:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.trustos_external_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "trustos_scanner" {
  role       = aws_iam_role.trustos_scanner.name
  policy_arn = aws_iam_policy.trustos_scanner.arn
}
```

#### Option C: AWS CloudFormation

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: TrustOS Scanner - Least Privilege Cross-Account Role

Parameters:
  TrustOSAccountId:
    Type: String
    Description: The AWS Account ID where TrustOS is deployed
  ExternalId:
    Type: String
    Description: External ID provided by TrustOS for confused-deputy protection

Resources:
  TrustOSScannerPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: TrustOSScannerPolicy
      Description: >-
        Least-privilege policy for TrustOS. Grants exactly 22 read-only
        configuration metadata actions. Zero data-plane access.
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: TrustOSS3ConfigAudit
            Effect: Allow
            Action:
              - s3:ListAllMyBuckets
              - s3:GetBucketPublicAccessBlock
              - s3:GetEncryptionConfiguration
              - s3:GetBucketVersioning
              - s3:GetBucketLogging
              - s3:GetBucketTagging
            Resource: '*'
          - Sid: TrustOSIAMConfigAudit
            Effect: Allow
            Action:
              - iam:ListUsers
              - iam:ListMFADevices
              - iam:ListAccessKeys
              - iam:GetAccessKeyLastUsed
              - iam:ListAttachedUserPolicies
            Resource: '*'
          - Sid: TrustOSEC2ConfigAudit
            Effect: Allow
            Action:
              - ec2:DescribeSecurityGroups
              - ec2:DescribeVolumes
              - ec2:DescribeInstances
            Resource: '*'
          - Sid: TrustOSRDSConfigAudit
            Effect: Allow
            Action:
              - rds:DescribeDBInstances
            Resource: '*'
          - Sid: TrustOSCloudTrailConfigAudit
            Effect: Allow
            Action:
              - cloudtrail:DescribeTrails
              - cloudtrail:GetTrailStatus
            Resource: '*'
          - Sid: TrustOSKMSConfigAudit
            Effect: Allow
            Action:
              - kms:ListKeys
              - kms:DescribeKey
              - kms:GetKeyRotationStatus
            Resource: '*'

  TrustOSScannerRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: TrustOSScannerRole
      ManagedPolicyArns:
        - !Ref TrustOSScannerPolicy
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${TrustOSAccountId}:root'
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId

Outputs:
  RoleArn:
    Description: Provide this Role ARN to TrustOS
    Value: !GetAtt TrustOSScannerRole.Arn
```

---

## What We Scan

The engine queries configuration metadata across the following AWS services:

- **S3** — Bucket public access blocks, encryption settings, versioning status, logging configuration
- **EC2** — Security group ingress rules, EBS volume encryption, instance metadata options
- **IAM** — Root account MFA status, access key age, overly permissive policies
- **RDS** — Encryption at rest, public accessibility flags, backup retention windows
- **CloudTrail** — Multi-region trail configuration, logging status, log file validation
- **KMS** — Key rotation status, key management type

All calls are read-only describe/get/list operations against the AWS control plane.

## What We Do Not Scan

There is no logic in this codebase that calls `s3:GetObject`, `dynamodb:Scan`, `rds:Select`, `sqs:ReceiveMessage`, or any other data-plane operation. The IAM permissions required by TrustOS do not include these actions and the scanner has no capability to access application data or user content.

The full list of actions TrustOS requires — and more importantly, what it does NOT require — is programmatically documented in `src/lib/scanners/aws/required-permissions.ts`.

---

## Authentication Model

TrustOS supports two authentication methods for connecting AWS accounts:

**Access Keys (development use)**
Provide an IAM `Access Key ID` and `Secret Access Key` with the custom `TrustOSScannerPolicy` attached. Suitable for testing and evaluation.

**IAM Role Assumption (production use)**
Create a cross-account IAM role with the `TrustOSScannerPolicy` attached in your AWS account. TrustOS assumes the role using STS with an `ExternalId` for confused-deputy protection. This is the recommended method for all production workloads. See [Setting Up the IAM Role](#setting-up-the-iam-role) for step-by-step instructions.

> **Important:** Do NOT attach `ReadOnlyAccess`, `ViewOnlyAccess`, or any other AWS managed policy. Use only the custom `TrustOSScannerPolicy` documented above to enforce least-privilege access.

---

## Policy Rules

The complete set of security rules is defined in `src/lib/scanners/aws/policy-rules.ts`. Each rule maps to one or more compliance framework controls (SOC 2, ISO 27001, HIPAA, GDPR).

Examples of default rules:

| Rule | Severity | Description |
|------|----------|-------------|
| S3 Public Access | Critical | Detects buckets with public access block disabled |
| EC2 Open SSH | Critical | Flags security groups allowing SSH from 0.0.0.0/0 |
| RDS No Encryption | High | Identifies RDS instances without KMS encryption at rest |
| IAM Root No MFA | Critical | Flags root accounts without multi-factor authentication |
| EBS Unencrypted | High | Detects EBS volumes without encryption enabled |
| KMS No Rotation | Medium | Flags KMS keys without automatic annual rotation |

---

## Using TrustOS

### Connecting AWS

1. Open the **Integrations** page from the sidebar.
2. Select **Add Account** under the AWS section.
3. Choose an authentication method:
   - For access keys, provide the `Access Key ID` and `Secret Access Key` from an IAM user with the `TrustOSScannerPolicy` attached.
   - For role assumption, provide the `Role ARN` of the TrustOS scanning role and the `External ID`.
4. Select your primary region and submit.

### Linking GitHub

TrustOS uses GitHub OAuth to authenticate your account. When you sign in with GitHub, TrustOS gains the ability to list your repositories and branches. It does not read or scan your source code.

1. Sign in using the **Continue with GitHub** button on the login page.
2. Navigate to **Integrations** and open the GitHub card.
3. Select your target repository from the dropdown.
4. Choose the base branch that remediation pull requests should target.
5. Confirm the selection.

All pull requests created by TrustOS will be opened against this repository and branch.

### Running Scans

1. Open the **Scans** page from the sidebar.
2. Locate your connected AWS account and select **Run Scan**.
3. The scanner will query your infrastructure across all configured services and regions.
4. Results are categorized by severity and mapped to compliance controls.

### Automated Remediation

When findings are identified, TrustOS can generate infrastructure-as-code fixes and deliver them as pull requests.

1. Open the **Findings** page and locate a finding.
2. Select **Remediate** on the finding.
3. Choose the output format: Terraform, CloudFormation, AWS CLI, or CDK.
4. Optionally enable pull request creation to push the fix directly to your linked repository.
5. If PR creation is disabled, the generated code is saved for manual review and application.

### Compliance Monitoring

The **Compliance** page displays your infrastructure posture against SOC 2, ISO 27001, HIPAA, and GDPR control frameworks. Scores update automatically after each scan. Remediating findings directly improves your compliance percentages.

---

## Project Structure

```
trustos-open-core/
  TrustOSScannerPolicy.json  — Custom IAM policy (22 actions, zero data access)
  src/
    lib/
      scanners/
        aws/
          index.ts                — Scanner orchestrator and entry point
          policy-rules.ts         — Security rule definitions and compliance mappings
          required-permissions.ts — Exhaustive permission inventory with justifications
          services/               — Per-service AWS scanning modules
    types/                        — Shared TypeScript interfaces
  package.json
  README.md
```

---

## License

This scanning engine is released for transparency and audit purposes. The full TrustOS platform, including the AI remediation engine, dashboard, and managed service, is proprietary. See [trust-os-sigma.vercel.app](https://trust-os-sigma.vercel.app) for the hosted product.
