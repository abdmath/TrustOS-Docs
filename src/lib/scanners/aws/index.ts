import { S3Client } from '@aws-sdk/client-s3';
import { IAMClient } from '@aws-sdk/client-iam';
import { EC2Client } from '@aws-sdk/client-ec2';
import { RDSClient } from '@aws-sdk/client-rds';
import { CloudTrailClient } from '@aws-sdk/client-cloudtrail';
import { KMSClient } from '@aws-sdk/client-kms';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { AWSCredentials, ScannedResource, ScanFinding, ScanProgress } from '../../../types';
import { scanS3 } from './services/s3';
import { scanIAM } from './services/iam';
import { scanEC2 } from './services/ec2';
import { scanRDS } from './services/rds';
import { scanCloudTrail } from './services/cloudtrail';
import { scanKMS } from './services/kms';
import { allPolicyRules, getRulesForService } from './policy-rules';

interface AWSClientConfig {
  region: string;
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
}

async function getClientConfig(creds: AWSCredentials): Promise<AWSClientConfig> {
  const config: AWSClientConfig = { region: creds.region };

  if (creds.roleArn) {
    // Assume Role for cross-account access
    const stsClient = new STSClient({
      region: creds.region,
      ...(creds.accessKeyId && creds.secretAccessKey ? {
        credentials: {
          accessKeyId: creds.accessKeyId,
          secretAccessKey: creds.secretAccessKey,
        }
      } : {}),
    });

    const assumeResponse = await stsClient.send(new AssumeRoleCommand({
      RoleArn: creds.roleArn,
      RoleSessionName: 'TrustOS-Scanner',
      DurationSeconds: 3600,
      ...(creds.externalId ? { ExternalId: creds.externalId } : {}),
    }));

    if (assumeResponse.Credentials) {
      config.credentials = {
        accessKeyId: assumeResponse.Credentials.AccessKeyId!,
        secretAccessKey: assumeResponse.Credentials.SecretAccessKey!,
        sessionToken: assumeResponse.Credentials.SessionToken,
      };
    }
  } else if (creds.accessKeyId && creds.secretAccessKey) {
    config.credentials = {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    };
  }

  return config;
}

export type ScanProgressCallback = (progress: ScanProgress) => void;

const SERVICES = ['S3', 'IAM', 'EC2', 'RDS', 'CloudTrail', 'KMS'] as const;

export async function runFullScan(
  credentials: AWSCredentials,
  services: string[] = [...SERVICES],
  onProgress?: ScanProgressCallback
): Promise<{ resources: ScannedResource[]; findings: ScanFinding[] }> {
  const allResources: ScannedResource[] = [];
  const allFindings: ScanFinding[] = [];
  const activeServices = services.filter(s => SERVICES.includes(s as typeof SERVICES[number]));

  const config = await getClientConfig(credentials);

  for (let i = 0; i < activeServices.length; i++) {
    const service = activeServices[i];

    onProgress?.({
      status: 'running',
      currentService: service,
      servicesCompleted: i,
      totalServices: activeServices.length,
      resourcesFound: allResources.length,
      findingsCount: allFindings.length,
      message: `Scanning ${service}...`,
    });

    let resources: ScannedResource[] = [];

    try {
      switch (service) {
        case 'S3':
          resources = await scanS3(new S3Client(config), config.region);
          break;
        case 'IAM':
          resources = await scanIAM(new IAMClient(config));
          break;
        case 'EC2':
          resources = await scanEC2(new EC2Client(config), config.region);
          break;
        case 'RDS':
          resources = await scanRDS(new RDSClient(config), config.region);
          break;
        case 'CloudTrail':
          resources = await scanCloudTrail(new CloudTrailClient(config), config.region);
          break;
        case 'KMS':
          resources = await scanKMS(new KMSClient(config), config.region);
          break;
      }
    } catch (error) {
      console.error(`Error scanning ${service}:`, error);
    }

    allResources.push(...resources);

    // Evaluate policy rules for discovered resources
    const serviceRules = getRulesForService(service);
    for (const resource of resources) {
      for (const rule of serviceRules) {
        try {
          const result = rule.check(resource);
          if (!result.passed) {
            allFindings.push({
              ruleId: rule.id,
              resource,
              severity: rule.severity,
              title: rule.title,
              description: rule.description,
              evidence: result.evidence,
              recommendation: rule.recommendation,
              frameworkMappings: rule.frameworkMappings,
            });
          }
        } catch (error) {
          console.error(`Error evaluating rule ${rule.id} on resource ${resource.arn}:`, error);
        }
      }
    }
  }

  onProgress?.({
    status: 'completed',
    currentService: 'Done',
    servicesCompleted: activeServices.length,
    totalServices: activeServices.length,
    resourcesFound: allResources.length,
    findingsCount: allFindings.length,
    message: `Scan completed. Found ${allResources.length} resources and ${allFindings.length} findings.`,
  });

  return { resources: allResources, findings: allFindings };
}

export { allPolicyRules };
