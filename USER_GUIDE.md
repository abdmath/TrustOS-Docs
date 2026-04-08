# 🛡️ TrustOS User Guide

Welcome to **TrustOS**! TrustOS is an AI-native DevSecOps platform designed to autonomously identify infrastructure misconfigurations, map them to compliance frameworks (like SOC 2, HIPAA, ISO 27001), and dynamically generate and deploy 'Infrastructure as Code' (IaC) fixes directly to your repository.

This guide will walk you through setting up your environment, connecting your cloud infrastructure, and automating your security remediations.

---

## 📑 Table of Contents
1. [Connecting Your AWS Environment](#1-connecting-your-aws-environment)
2. [Linking Your GitHub Repository](#2-linking-your-github-repository)
3. [Running Security Scans](#3-running-security-scans)
4. [AI-Automated Remediation (The Magic)](#4-ai-automated-remediation)
5. [Monitoring Compliance Posture](#5-monitoring-compliance-posture)

---

## 1. Connecting Your AWS Environment
Before TrustOS can assess your cloud security, you must connect an AWS account. TrustOS safely assumes roles or uses access keys to scan your environment strictly for metadata—it will **never** alter your infrastructure directly during a scan.

**Step-by-Step Instructions:**
1. Navigate to the **Integrations** tab on the left sidebar.
2. Click the **+ Add Account** button under the AWS section.
3. Choose your Authentication Method:
   - **Access Keys (Development Environment):** Recommended for quick testing. You will need to provide an `Access Key ID` and a `Secret Access Key` generated from the AWS IAM Console. 
   - **Assume IAM Role (Production):** The enterprise standard. Provide the `Role ARN` of the TrustOS auditing role you created in AWS. You can optionally provide an `External ID` to prevent confused-deputy attacks.
4. Enter an optional Account Name (e.g., "Production AWS") and click **Connect Account**.
5. Look for the sliding green success notification! 🟩

---

## 2. Linking Your GitHub Repository
To allow TrustOS to automatically create Pull Requests for security fixes instead of having to manually deploy them, you must connect your GitHub Application.

**Step-by-Step Instructions:**
1. Navigate to the **Integrations** tab.
2. Click **+ Connect** under the GitHub App section.
3. You will be prompted for three fields:
   - **Installation ID:** The unique ID provided when you install the TrustOS App onto your GitHub Organization/Account.
   - **Repository Owner:** The GitHub handle or Organization name (e.g., `octocat`).
   - **Repository Name:** The exact name of the destination repository.
4. Click **Connect App**. 

---

## 3. Running Security Scans
Once AWS is connected, it’s time to detect misconfigurations. 

1. Go to the **Scans** tab on the sidebar.
2. Under "Connected Accounts," find your newly linked AWS Account.
3. Click **🔍 Run Scan**.
4. The scanner will interrogate your AWS environment across multiple services (S3, EC2, IAM, RDS) looking for missing encryptions, public-facing elements, or overly permissive policies.
5. Wait for the green "Scan completed successfully!" notification.

---

## 4. AI-Automated Remediation 
This is the core differentiating feature of TrustOS. Instead of simply telling you what is broken, TrustOS will write the exact Terraform, CloudFormation, or CDK code required to fix it!

### Generating a Fix
1. Head over to the **Findings** tab.
2. You will see a list of violations categorized by severity (`CRITICAL`, `HIGH`, `MEDIUM`).
3. On any finding, click the **✨ Remediate** button.
4. The Configuration Modal will appear:
   - **Code Format:** Choose your preferred output language (HashiCorp Terraform, AWS CloudFormation, AWS CLI scripts, or AWS CDK).
   - **Create PR Checkbox:** 
     - *Checked:* TrustOS will ping the LLM, generate the code, and immediately open a Pull Request in the GitHub repository you connected earlier.
     - *Unchecked (Silent Mode):* TrustOS will generate the fix, save it to the database, and do nothing else. 
5. Click **Generate Fix ✨**.

### Applying the Fix
1. Navigate to the **Remediations** tab.
2. Here, you will see all successfully generated remediations. 
3. If you enabled PR creation, you can click **🔗 View PR** to go straight to GitHub and merge the code.
4. If you chose manual mode, click **📝 View Code**, copy the generated script, and apply it to your infrastructure pipeline manually.
5. The finding's status is automatically upgraded to `REMEDIATED`!

---

## 5. Monitoring Compliance Posture
To prove to auditors that your infrastructure is secure:

1. Click on the **Compliance** tab.
2. TrustOS continuously maps your security findings against Major Frameworks (such as SOC 2, ISO 27001, and HIPAA).
3. The dashboard will break down the exact percentage of passing infrastructure controls, giving you a real-time risk metric. 
4. Every time you merge a TrustOS remediation, your score will automatically rise during the next scan.

---
*Powered by TrustOS — Active Cloud Defense.*
