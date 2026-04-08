import { S3Client, ListBucketsCommand, GetBucketEncryptionCommand, GetBucketVersioningCommand, GetBucketLoggingCommand, GetPublicAccessBlockCommand, GetBucketTaggingCommand } from '@aws-sdk/client-s3';
import { ScannedResource } from '@/types';

export async function scanS3(client: S3Client, region: string): Promise<ScannedResource[]> {
  const resources: ScannedResource[] = [];

  try {
    const bucketsResponse = await client.send(new ListBucketsCommand({}));
    const buckets = bucketsResponse.Buckets || [];

    for (const bucket of buckets) {
      if (!bucket.Name) continue;

      const config: Record<string, unknown> = {
        bucketName: bucket.Name,
        creationDate: bucket.CreationDate?.toISOString(),
      };

      // Check Public Access Block
      try {
        const pabResponse = await client.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name })) as unknown as Record<string, unknown>;
        const pabConfig = (pabResponse.PublicAccessBlockConfiguration || {}) as Record<string, boolean>;
        config.publicAccessBlock = {
          BlockPublicAcls: pabConfig.BlockPublicAcls ?? false,
          IgnorePublicAcls: pabConfig.IgnorePublicAcls ?? false,
          BlockPublicPolicy: pabConfig.BlockPublicPolicy ?? false,
          RestrictPublicBuckets: pabConfig.RestrictPublicBuckets ?? false,
        };
      } catch {
        config.publicAccessBlock = null;
      }

      // Check Encryption
      try {
        const encResponse = await client.send(new GetBucketEncryptionCommand({ Bucket: bucket.Name }));
        const rules = encResponse.ServerSideEncryptionConfiguration?.Rules;
        if (rules && rules.length > 0) {
          config.encryption = {
            algorithm: rules[0].ApplyServerSideEncryptionByDefault?.SSEAlgorithm,
            kmsMasterKeyId: rules[0].ApplyServerSideEncryptionByDefault?.KMSMasterKeyID,
          };
        }
      } catch {
        config.encryption = null;
      }

      // Check Versioning
      try {
        const verResponse = await client.send(new GetBucketVersioningCommand({ Bucket: bucket.Name }));
        config.versioningStatus = verResponse.Status || 'Disabled';
      } catch {
        config.versioningStatus = 'Unknown';
      }

      // Check Logging
      try {
        const logResponse = await client.send(new GetBucketLoggingCommand({ Bucket: bucket.Name }));
        config.loggingEnabled = !!logResponse.LoggingEnabled;
        if (logResponse.LoggingEnabled) {
          config.loggingTargetBucket = logResponse.LoggingEnabled.TargetBucket;
        }
      } catch {
        config.loggingEnabled = false;
      }

      // Get Tags
      let tags: Record<string, string> = {};
      try {
        const tagResponse = await client.send(new GetBucketTaggingCommand({ Bucket: bucket.Name }));
        tags = (tagResponse.TagSet || []).reduce((acc, tag) => {
          if (tag.Key && tag.Value) acc[tag.Key] = tag.Value;
          return acc;
        }, {} as Record<string, string>);
      } catch {
        // No tags
      }

      resources.push({
        arn: `arn:aws:s3:::${bucket.Name}`,
        resourceType: 's3_bucket',
        service: 'S3',
        region,
        name: bucket.Name,
        configuration: config,
        tags,
      });
    }
  } catch (error) {
    console.error('Error scanning S3:', error);
  }

  return resources;
}
