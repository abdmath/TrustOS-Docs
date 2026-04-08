# TrustOS — Open-Core AWS Scanner

This repository contains the open-source auditing engine that powers [TrustOS](https://trust-os-sigma.vercel.app). It is published to provide full transparency into the exact scanning logic executed against your AWS infrastructure.

By reading this source, you can verify a critical guarantee: **TrustOS interacts exclusively with the AWS Configuration Control Plane. It does not — and cannot — read your application data, objects, or PII.**

---

## Table of Contents

- [Architecture](#architecture)
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

## What We Scan

The engine queries configuration metadata across the following AWS services:

- **S3** — Bucket public access blocks, encryption settings, versioning status, logging configuration
- **EC2** — Security group ingress rules, EBS volume encryption, instance metadata options
- **IAM** — Root account MFA status, access key age, overly permissive policies
- **RDS** — Encryption at rest, public accessibility flags, backup retention windows
- **KMS** — Key rotation status, key management type

All calls are read-only describe/get/list operations against the AWS control plane.

## What We Do Not Scan

There is no logic in this codebase that calls `s3:GetObject`, `dynamodb:Scan`, `rds:Select`, `sqs:ReceiveMessage`, or any other data-plane operation. The IAM permissions required by TrustOS do not include these actions and the scanner has no capability to access application data or user content.

---

## Authentication Model

TrustOS supports two authentication methods for connecting AWS accounts:

**Access Keys (development use)**
Provide an IAM `Access Key ID` and `Secret Access Key` with read-only permissions. Suitable for testing and evaluation.

**IAM Role Assumption (production use)**
Create a cross-account IAM role with `ReadOnlyAccess` in your AWS account. TrustOS assumes the role using STS with an optional `ExternalId` for confused-deputy protection. This is the recommended method for all production workloads.

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
   - For access keys, provide the `Access Key ID` and `Secret Access Key`.
   - For role assumption, provide the `Role ARN` and optionally an `External ID`.
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
  src/
    lib/
      scanners/
        aws/
          index.ts          — Scanner orchestrator and entry point
          policy-rules.ts   — Security rule definitions and compliance mappings
          services/         — Per-service AWS scanning modules
    types/                  — Shared TypeScript interfaces
  package.json
  README.md
```

---

## License

This scanning engine is released for transparency and audit purposes. The full TrustOS platform, including the AI remediation engine, dashboard, and managed service, is proprietary. See [trust-os-sigma.vercel.app](https://trust-os-sigma.vercel.app) for the hosted product.
