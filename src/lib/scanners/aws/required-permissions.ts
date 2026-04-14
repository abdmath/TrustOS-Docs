/**
 * TrustOS Required IAM Permissions
 * 
 * This file documents every AWS IAM action the TrustOS scanner requires.
 * Each permission is mapped to the scanner module that uses it and a
 * justification for why it is needed.
 *
 * PRIVACY GUARANTEE:
 * Every action listed here is a control-plane metadata read operation.
 * TrustOS does NOT and CANNOT access user data, objects, database contents,
 * log entries, message queues, or any other data-plane resource.
 *
 * Explicitly excluded actions (examples of what we DO NOT request):
 * - s3:GetObject, s3:ListBucket (reading/listing files)
 * - dynamodb:GetItem, dynamodb:Scan (reading database items)
 * - rds:DownloadDBLogFilePortion (reading database logs)
 * - sqs:ReceiveMessage (reading queue messages)
 * - secretsmanager:GetSecretValue (reading secrets)
 * - ssm:GetParameter (reading parameter store values)
 * - logs:GetLogEvents (reading CloudWatch logs)
 * - lambda:GetFunction (could expose environment variable secrets)
 */

export interface RequiredPermission {
  /** The IAM action string (e.g., "s3:ListAllMyBuckets") */
  action: string;
  /** The AWS service this permission belongs to */
  service: string;
  /** The scanner module that calls this API */
  usedBy: string;
  /** The AWS SDK command that requires this permission */
  sdkCommand: string;
  /** Why TrustOS needs this permission for misconfiguration detection */
  justification: string;
}

/**
 * Complete, exhaustive list of every IAM permission TrustOS requires.
 * If a permission is not in this list, TrustOS does not use it.
 */
export const REQUIRED_PERMISSIONS: RequiredPermission[] = [

  // ==================== STS (Authentication) ====================
  {
    action: 'sts:AssumeRole',
    service: 'STS',
    usedBy: 'scanners/aws/index.ts',
    sdkCommand: 'AssumeRoleCommand',
    justification: 'Cross-account role assumption for scanning customer AWS accounts without static credentials.',
  },
  {
    action: 'sts:GetCallerIdentity',
    service: 'STS',
    usedBy: 'api/integrations/route.ts',
    sdkCommand: 'GetCallerIdentityCommand',
    justification: 'Validates the assumed role identity during AWS account onboarding.',
  },

  // ==================== S3 (Bucket Configuration) ====================
  {
    action: 's3:ListAllMyBuckets',
    service: 'S3',
    usedBy: 'scanners/aws/services/s3.ts',
    sdkCommand: 'ListBucketsCommand',
    justification: 'Enumerates all S3 buckets in the account to discover resources for scanning.',
  },
  {
    action: 's3:GetBucketPublicAccessBlock',
    service: 'S3',
    usedBy: 'scanners/aws/services/s3.ts',
    sdkCommand: 'GetPublicAccessBlockCommand',
    justification: 'Detects whether public access block settings are enabled — the #1 S3 misconfiguration.',
  },
  {
    action: 's3:GetEncryptionConfiguration',
    service: 'S3',
    usedBy: 'scanners/aws/services/s3.ts',
    sdkCommand: 'GetBucketEncryptionCommand',
    justification: 'Detects whether server-side encryption (SSE-S3 or SSE-KMS) is configured at rest.',
  },
  {
    action: 's3:GetBucketVersioning',
    service: 'S3',
    usedBy: 'scanners/aws/services/s3.ts',
    sdkCommand: 'GetBucketVersioningCommand',
    justification: 'Detects whether versioning is enabled for accidental deletion protection (SOC2-CC6.1).',
  },
  {
    action: 's3:GetBucketLogging',
    service: 'S3',
    usedBy: 'scanners/aws/services/s3.ts',
    sdkCommand: 'GetBucketLoggingCommand',
    justification: 'Detects whether server access logging is enabled for audit compliance (HIPAA-164.312(b)).',
  },
  {
    action: 's3:GetBucketTagging',
    service: 'S3',
    usedBy: 'scanners/aws/services/s3.ts',
    sdkCommand: 'GetBucketTaggingCommand',
    justification: 'Reads resource tags for asset inventory and labeling in the dashboard.',
  },

  // ==================== IAM (User & Policy Configuration) ====================
  {
    action: 'iam:ListUsers',
    service: 'IAM',
    usedBy: 'scanners/aws/services/iam.ts',
    sdkCommand: 'ListUsersCommand',
    justification: 'Enumerates all IAM users to discover principals for MFA and access key auditing.',
  },
  {
    action: 'iam:ListMFADevices',
    service: 'IAM',
    usedBy: 'scanners/aws/services/iam.ts',
    sdkCommand: 'ListMFADevicesCommand',
    justification: 'Detects whether multi-factor authentication is enabled for each IAM user.',
  },
  {
    action: 'iam:ListAccessKeys',
    service: 'IAM',
    usedBy: 'scanners/aws/services/iam.ts',
    sdkCommand: 'ListAccessKeysCommand',
    justification: 'Detects existence of access keys to audit for stale or unused credentials.',
  },
  {
    action: 'iam:GetAccessKeyLastUsed',
    service: 'IAM',
    usedBy: 'scanners/aws/services/iam.ts',
    sdkCommand: 'GetAccessKeyLastUsedCommand',
    justification: 'Determines when each access key was last used to detect stale keys (90+ day rule).',
  },
  {
    action: 'iam:ListAttachedUserPolicies',
    service: 'IAM',
    usedBy: 'scanners/aws/services/iam.ts',
    sdkCommand: 'ListAttachedUserPoliciesCommand',
    justification: 'Lists policy ARNs/names attached to users to detect overly permissive policies like AdministratorAccess. Does NOT read policy document contents.',
  },

  // ==================== EC2 (Network & Volume Configuration) ====================
  {
    action: 'ec2:DescribeSecurityGroups',
    service: 'EC2',
    usedBy: 'scanners/aws/services/ec2.ts',
    sdkCommand: 'DescribeSecurityGroupsCommand',
    justification: 'Reads security group ingress rules to detect open ports (0.0.0.0/0 on SSH, RDP, databases).',
  },
  {
    action: 'ec2:DescribeVolumes',
    service: 'EC2',
    usedBy: 'scanners/aws/services/ec2.ts',
    sdkCommand: 'DescribeVolumesCommand',
    justification: 'Detects unencrypted EBS volumes — required for encryption-at-rest compliance.',
  },
  {
    action: 'ec2:DescribeInstances',
    service: 'EC2',
    usedBy: 'scanners/aws/services/ec2.ts',
    sdkCommand: 'DescribeInstancesCommand',
    justification: 'Inventories EC2 instances with network exposure context (public IPs, security group assignments).',
  },

  // ==================== RDS (Database Configuration) ====================
  {
    action: 'rds:DescribeDBInstances',
    service: 'RDS',
    usedBy: 'scanners/aws/services/rds.ts',
    sdkCommand: 'DescribeDBInstancesCommand',
    justification: 'Reads RDS instance metadata to detect public accessibility, missing encryption, and short backup retention.',
  },

  // ==================== CloudTrail (Audit Logging Configuration) ====================
  {
    action: 'cloudtrail:DescribeTrails',
    service: 'CloudTrail',
    usedBy: 'scanners/aws/services/cloudtrail.ts',
    sdkCommand: 'DescribeTrailsCommand',
    justification: 'Detects whether audit trails exist and are configured for multi-region logging.',
  },
  {
    action: 'cloudtrail:GetTrailStatus',
    service: 'CloudTrail',
    usedBy: 'scanners/aws/services/cloudtrail.ts',
    sdkCommand: 'GetTrailStatusCommand',
    justification: 'Detects whether a CloudTrail trail is actively logging events.',
  },

  // ==================== KMS (Key Management Configuration) ====================
  {
    action: 'kms:ListKeys',
    service: 'KMS',
    usedBy: 'scanners/aws/services/kms.ts',
    sdkCommand: 'ListKeysCommand',
    justification: 'Enumerates customer-managed KMS keys for rotation audit.',
  },
  {
    action: 'kms:DescribeKey',
    service: 'KMS',
    usedBy: 'scanners/aws/services/kms.ts',
    sdkCommand: 'DescribeKeyCommand',
    justification: 'Reads key metadata (manager type, state, usage) to filter AWS-managed keys from audit.',
  },
  {
    action: 'kms:GetKeyRotationStatus',
    service: 'KMS',
    usedBy: 'scanners/aws/services/kms.ts',
    sdkCommand: 'GetKeyRotationStatusCommand',
    justification: 'Detects whether automatic annual key rotation is enabled on customer-managed keys.',
  },
];

/**
 * Returns the list of IAM actions required for a specific service.
 */
export function getPermissionsForService(service: string): RequiredPermission[] {
  return REQUIRED_PERMISSIONS.filter(p => p.service === service);
}

/**
 * Returns a flat array of all IAM action strings (useful for policy generation).
 */
export function getAllActionStrings(): string[] {
  return REQUIRED_PERMISSIONS.map(p => p.action);
}

/**
 * Returns the total number of unique IAM actions required.
 */
export function getPermissionCount(): number {
  return new Set(REQUIRED_PERMISSIONS.map(p => p.action)).size;
}
