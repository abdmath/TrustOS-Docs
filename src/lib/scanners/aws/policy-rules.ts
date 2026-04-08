import { PolicyRule, ScannedResource } from '@/types';

// ==================== S3 POLICY RULES ====================

const s3PublicAccessDisabled: PolicyRule = {
  id: 's3-public-access-disabled',
  service: 'S3',
  severity: 'critical',
  title: 'S3 Bucket Public Access Not Blocked',
  description: 'S3 bucket does not have all public access block settings enabled, potentially exposing data to the internet.',
  recommendation: 'Enable all four S3 Block Public Access settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.',
  frameworkMappings: ['SOC2-CC6.1', 'SOC2-CC6.6', 'ISO27001-A.8.3', 'HIPAA-164.312(a)(1)', 'GDPR-Art.32'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const pab = config.publicAccessBlock as Record<string, boolean> | undefined;
    const allBlocked = pab &&
      pab.BlockPublicAcls === true &&
      pab.IgnorePublicAcls === true &&
      pab.BlockPublicPolicy === true &&
      pab.RestrictPublicBuckets === true;
    return {
      passed: !!allBlocked,
      evidence: { publicAccessBlock: pab || 'not configured' },
      details: allBlocked ? 'All public access blocks enabled' : 'One or more public access blocks are disabled'
    };
  }
};

const s3EncryptionEnabled: PolicyRule = {
  id: 's3-encryption-enabled',
  service: 'S3',
  severity: 'high',
  title: 'S3 Bucket Server-Side Encryption Not Enabled',
  description: 'S3 bucket does not have default server-side encryption configured.',
  recommendation: 'Enable default encryption on the S3 bucket using SSE-S3 (AES-256) or SSE-KMS.',
  frameworkMappings: ['SOC2-CC6.7', 'ISO27001-A.8.24', 'HIPAA-164.312(a)(2)(iv)', 'GDPR-Art.32'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const encryption = config.encryption as Record<string, unknown> | undefined;
    const hasEncryption = !!encryption && Object.keys(encryption).length > 0;
    return {
      passed: hasEncryption,
      evidence: { encryption: encryption || 'not configured' },
      details: hasEncryption ? 'Server-side encryption is enabled' : 'No default encryption configured'
    };
  }
};

const s3VersioningEnabled: PolicyRule = {
  id: 's3-versioning-enabled',
  service: 'S3',
  severity: 'medium',
  title: 'S3 Bucket Versioning Not Enabled',
  description: 'S3 bucket does not have versioning enabled, risking data loss from accidental deletion.',
  recommendation: 'Enable versioning on the S3 bucket to protect against accidental deletion and provide data recovery.',
  frameworkMappings: ['SOC2-CC6.1', 'ISO27001-A.8.13', 'HIPAA-164.312(c)(1)'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const versioning = config.versioningStatus as string | undefined;
    const enabled = versioning === 'Enabled';
    return {
      passed: enabled,
      evidence: { versioningStatus: versioning || 'not configured' },
      details: enabled ? 'Versioning is enabled' : 'Versioning is not enabled'
    };
  }
};

const s3LoggingEnabled: PolicyRule = {
  id: 's3-logging-enabled',
  service: 'S3',
  severity: 'medium',
  title: 'S3 Bucket Access Logging Not Enabled',
  description: 'S3 bucket does not have server access logging enabled.',
  recommendation: 'Enable server access logging to track requests made to the bucket for security and audit purposes.',
  frameworkMappings: ['SOC2-CC7.1', 'SOC2-CC7.2', 'ISO27001-A.8.15', 'HIPAA-164.312(b)'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const logging = config.loggingEnabled as boolean | undefined;
    return {
      passed: !!logging,
      evidence: { loggingEnabled: logging ?? false },
      details: logging ? 'Access logging is enabled' : 'Access logging is not enabled'
    };
  }
};

// ==================== IAM POLICY RULES ====================

const iamMfaEnabled: PolicyRule = {
  id: 'iam-mfa-enabled',
  service: 'IAM',
  severity: 'critical',
  title: 'IAM User Does Not Have MFA Enabled',
  description: 'IAM user does not have multi-factor authentication enabled, increasing risk of unauthorized access.',
  recommendation: 'Enable MFA for the IAM user. Use virtual MFA devices or hardware security keys.',
  frameworkMappings: ['SOC2-CC6.1', 'SOC2-CC6.2', 'ISO27001-A.8.5', 'HIPAA-164.312(d)', 'GDPR-Art.32'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const hasMfa = config.mfaEnabled as boolean | undefined;
    return {
      passed: !!hasMfa,
      evidence: { mfaEnabled: hasMfa ?? false },
      details: hasMfa ? 'MFA is enabled' : 'MFA is not enabled'
    };
  }
};

const iamOverlyPermissivePolicy: PolicyRule = {
  id: 'iam-overly-permissive-policy',
  service: 'IAM',
  severity: 'critical',
  title: 'IAM Policy Allows Wildcard Actions',
  description: 'IAM user or role has a policy attached that allows all actions (*) on all resources, violating least privilege.',
  recommendation: 'Replace overly permissive policies with specific permissions following the principle of least privilege.',
  frameworkMappings: ['SOC2-CC6.1', 'SOC2-CC6.3', 'ISO27001-A.5.15', 'ISO27001-A.8.3', 'HIPAA-164.312(a)(1)', 'GDPR-Art.25'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const policies = config.attachedPolicies as Array<Record<string, string>> | undefined;
    const hasWildcard = policies?.some(p => p.policyName === 'AdministratorAccess' || p.policyArn?.includes('AdministratorAccess'));
    return {
      passed: !hasWildcard,
      evidence: { attachedPolicies: policies || [] },
      details: hasWildcard ? 'User has AdministratorAccess or wildcard policy' : 'No overly permissive policies detected'
    };
  }
};

const iamUnusedAccessKeys: PolicyRule = {
  id: 'iam-unused-access-keys',
  service: 'IAM',
  severity: 'high',
  title: 'IAM Access Key Not Used in 90+ Days',
  description: 'IAM user has access keys that have not been used in over 90 days, indicating potential unnecessary access.',
  recommendation: 'Deactivate or delete unused access keys. Rotate active keys regularly.',
  frameworkMappings: ['SOC2-CC6.1', 'SOC2-CC6.2', 'ISO27001-A.5.15', 'HIPAA-164.312(a)(1)'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const accessKeys = config.accessKeys as Array<Record<string, unknown>> | undefined;
    const now = Date.now();
    const ninetyDays = 90 * 24 * 60 * 60 * 1000;
    const hasUnused = accessKeys?.some(key => {
      const lastUsed = key.lastUsedDate as string | undefined;
      if (!lastUsed) return true;
      return (now - new Date(lastUsed).getTime()) > ninetyDays;
    });
    return {
      passed: !hasUnused,
      evidence: { accessKeys: accessKeys?.map(k => ({ keyId: k.accessKeyId, lastUsed: k.lastUsedDate, status: k.status })) || [] },
      details: hasUnused ? 'One or more access keys unused for 90+ days' : 'All access keys recently used'
    };
  }
};

const iamRootAccountUsage: PolicyRule = {
  id: 'iam-root-account-no-access-keys',
  service: 'IAM',
  severity: 'critical',
  title: 'Root Account Has Active Access Keys',
  description: 'The AWS root account has active access keys, which is a severe security risk.',
  recommendation: 'Delete root account access keys and use IAM users/roles instead.',
  frameworkMappings: ['SOC2-CC6.1', 'SOC2-CC6.2', 'ISO27001-A.8.2', 'HIPAA-164.312(a)(1)'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const isRoot = config.isRoot as boolean | undefined;
    const accessKeys = config.accessKeys as Array<Record<string, unknown>> | undefined;
    if (!isRoot) return { passed: true, evidence: { isRoot: false }, details: 'Not root account' };
    const hasActiveKeys = accessKeys?.some(k => k.status === 'Active');
    return {
      passed: !hasActiveKeys,
      evidence: { isRoot: true, hasActiveKeys: !!hasActiveKeys },
      details: hasActiveKeys ? 'Root account has active access keys' : 'Root account does not have active access keys'
    };
  }
};

// ==================== EC2/VPC POLICY RULES ====================

const ec2OpenSecurityGroup: PolicyRule = {
  id: 'ec2-no-open-security-groups',
  service: 'EC2',
  severity: 'critical',
  title: 'Security Group Allows Unrestricted Inbound Access',
  description: 'Security group has inbound rules allowing traffic from 0.0.0.0/0 on sensitive ports (SSH, RDP, Database).',
  recommendation: 'Restrict security group inbound rules to specific IP ranges. Never allow 0.0.0.0/0 on management ports.',
  frameworkMappings: ['SOC2-CC6.1', 'SOC2-CC6.6', 'ISO27001-A.8.20', 'HIPAA-164.312(e)(1)', 'GDPR-Art.32'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const ingressRules = config.ingressRules as Array<Record<string, unknown>> | undefined;
    const sensitivePorts = [22, 3389, 3306, 5432, 1433, 27017, 6379, 9200];
    const openRules = ingressRules?.filter(rule => {
      const cidr = rule.cidrIp as string;
      const fromPort = rule.fromPort as number;
      const toPort = rule.toPort as number;
      if (cidr !== '0.0.0.0/0' && cidr !== '::/0') return false;
      return sensitivePorts.some(p => p >= fromPort && p <= toPort) || (fromPort === 0 && toPort === 65535);
    }) || [];
    return {
      passed: openRules.length === 0,
      evidence: { openIngressRules: openRules },
      details: openRules.length > 0 ? `${openRules.length} rule(s) allow unrestricted access on sensitive ports` : 'No unrestricted inbound rules on sensitive ports'
    };
  }
};

const ec2UnencryptedVolumes: PolicyRule = {
  id: 'ec2-ebs-encryption',
  service: 'EC2',
  severity: 'high',
  title: 'EBS Volume Not Encrypted',
  description: 'EBS volume is not encrypted, potentially exposing data at rest.',
  recommendation: 'Enable encryption for all EBS volumes. Use AWS-managed or customer-managed KMS keys.',
  frameworkMappings: ['SOC2-CC6.7', 'ISO27001-A.8.24', 'HIPAA-164.312(a)(2)(iv)', 'GDPR-Art.32'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const encrypted = config.encrypted as boolean | undefined;
    return {
      passed: !!encrypted,
      evidence: { encrypted: encrypted ?? false },
      details: encrypted ? 'Volume is encrypted' : 'Volume is not encrypted'
    };
  }
};

// ==================== RDS POLICY RULES ====================

const rdsEncryptionEnabled: PolicyRule = {
  id: 'rds-encryption-enabled',
  service: 'RDS',
  severity: 'critical',
  title: 'RDS Instance Not Encrypted',
  description: 'RDS database instance does not have encryption at rest enabled.',
  recommendation: 'Enable encryption at rest for the RDS instance. Note: This requires creating a new encrypted instance and migrating data.',
  frameworkMappings: ['SOC2-CC6.7', 'ISO27001-A.8.24', 'HIPAA-164.312(a)(2)(iv)', 'GDPR-Art.32'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const encrypted = config.storageEncrypted as boolean | undefined;
    return {
      passed: !!encrypted,
      evidence: { storageEncrypted: encrypted ?? false },
      details: encrypted ? 'Storage encryption is enabled' : 'Storage encryption is not enabled'
    };
  }
};

const rdsPublicAccess: PolicyRule = {
  id: 'rds-no-public-access',
  service: 'RDS',
  severity: 'critical',
  title: 'RDS Instance Is Publicly Accessible',
  description: 'RDS database instance is publicly accessible, exposing it to potential attacks from the internet.',
  recommendation: 'Disable public accessibility and use VPC security groups to control access.',
  frameworkMappings: ['SOC2-CC6.1', 'SOC2-CC6.6', 'ISO27001-A.8.20', 'HIPAA-164.312(a)(1)', 'GDPR-Art.32'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const publiclyAccessible = config.publiclyAccessible as boolean | undefined;
    return {
      passed: !publiclyAccessible,
      evidence: { publiclyAccessible: publiclyAccessible ?? false },
      details: publiclyAccessible ? 'Instance is publicly accessible' : 'Instance is not publicly accessible'
    };
  }
};

const rdsBackupEnabled: PolicyRule = {
  id: 'rds-backup-retention',
  service: 'RDS',
  severity: 'high',
  title: 'RDS Backup Retention Period Too Short',
  description: 'RDS instance backup retention period is less than 7 days.',
  recommendation: 'Set backup retention period to at least 7 days (14-35 recommended for production).',
  frameworkMappings: ['SOC2-CC6.1', 'ISO27001-A.8.13', 'HIPAA-164.312(c)(1)'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const retention = config.backupRetentionPeriod as number | undefined;
    const sufficient = (retention ?? 0) >= 7;
    return {
      passed: sufficient,
      evidence: { backupRetentionPeriod: retention ?? 0 },
      details: sufficient ? `Backup retention is ${retention} days` : `Backup retention is only ${retention ?? 0} days (minimum 7 required)`
    };
  }
};

const rdsMultiAz: PolicyRule = {
  id: 'rds-multi-az',
  service: 'RDS',
  severity: 'medium',
  title: 'RDS Instance Not Multi-AZ',
  description: 'RDS instance does not have Multi-AZ deployment enabled, reducing availability.',
  recommendation: 'Enable Multi-AZ deployment for production databases to ensure high availability.',
  frameworkMappings: ['SOC2-A1.2', 'ISO27001-A.8.14'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const multiAz = config.multiAZ as boolean | undefined;
    return {
      passed: !!multiAz,
      evidence: { multiAZ: multiAz ?? false },
      details: multiAz ? 'Multi-AZ is enabled' : 'Multi-AZ is not enabled'
    };
  }
};

// ==================== CLOUDTRAIL POLICY RULES ====================

const cloudtrailEnabled: PolicyRule = {
  id: 'cloudtrail-enabled',
  service: 'CloudTrail',
  severity: 'critical',
  title: 'CloudTrail Logging Not Enabled',
  description: 'CloudTrail is not enabled or not configured for all regions, leaving gaps in audit trail.',
  recommendation: 'Enable CloudTrail with multi-region logging and log file validation.',
  frameworkMappings: ['SOC2-CC7.1', 'SOC2-CC7.2', 'ISO27001-A.8.15', 'HIPAA-164.312(b)', 'GDPR-Art.33'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const isMultiRegion = config.isMultiRegionTrail as boolean | undefined;
    const isLogging = config.isLogging as boolean | undefined;
    const logValidation = config.logFileValidationEnabled as boolean | undefined;
    const allGood = !!isMultiRegion && !!isLogging && !!logValidation;
    return {
      passed: allGood,
      evidence: { isMultiRegionTrail: isMultiRegion, isLogging, logFileValidationEnabled: logValidation },
      details: allGood ? 'CloudTrail is properly configured' : 'CloudTrail is missing one or more recommended settings'
    };
  }
};

// ==================== KMS POLICY RULES ====================

const kmsKeyRotation: PolicyRule = {
  id: 'kms-key-rotation-enabled',
  service: 'KMS',
  severity: 'medium',
  title: 'KMS Key Automatic Rotation Not Enabled',
  description: 'KMS customer-managed key does not have automatic annual rotation enabled.',
  recommendation: 'Enable automatic key rotation for customer-managed KMS keys.',
  frameworkMappings: ['SOC2-CC6.7', 'ISO27001-A.8.24', 'HIPAA-164.312(a)(2)(iv)'],
  check: (resource: ScannedResource) => {
    const config = resource.configuration;
    const rotationEnabled = config.keyRotationEnabled as boolean | undefined;
    return {
      passed: !!rotationEnabled,
      evidence: { keyRotationEnabled: rotationEnabled ?? false },
      details: rotationEnabled ? 'Key rotation is enabled' : 'Key rotation is not enabled'
    };
  }
};

// ==================== EXPORT ALL RULES ====================

export const allPolicyRules: PolicyRule[] = [
  // S3
  s3PublicAccessDisabled,
  s3EncryptionEnabled,
  s3VersioningEnabled,
  s3LoggingEnabled,
  // IAM
  iamMfaEnabled,
  iamOverlyPermissivePolicy,
  iamUnusedAccessKeys,
  iamRootAccountUsage,
  // EC2/VPC
  ec2OpenSecurityGroup,
  ec2UnencryptedVolumes,
  // RDS
  rdsEncryptionEnabled,
  rdsPublicAccess,
  rdsBackupEnabled,
  rdsMultiAz,
  // CloudTrail
  cloudtrailEnabled,
  // KMS
  kmsKeyRotation,
];

export function getRulesForService(service: string): PolicyRule[] {
  return allPolicyRules.filter(r => r.service === service);
}

export function getRuleById(id: string): PolicyRule | undefined {
  return allPolicyRules.find(r => r.id === id);
}
