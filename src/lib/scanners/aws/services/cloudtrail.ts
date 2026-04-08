import { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } from '@aws-sdk/client-cloudtrail';
import { ScannedResource } from '@/types';

export async function scanCloudTrail(client: CloudTrailClient, region: string): Promise<ScannedResource[]> {
  const resources: ScannedResource[] = [];

  try {
    const response = await client.send(new DescribeTrailsCommand({}));
    for (const trail of response.trailList || []) {
      if (!trail.TrailARN || !trail.Name) continue;

      let isLogging = false;
      try {
        const statusResponse = await client.send(new GetTrailStatusCommand({ Name: trail.Name }));
        isLogging = statusResponse.IsLogging ?? false;
      } catch {
        // ignore
      }

      resources.push({
        arn: trail.TrailARN,
        resourceType: 'cloudtrail_trail',
        service: 'CloudTrail',
        region,
        name: trail.Name,
        configuration: {
          trailName: trail.Name,
          s3BucketName: trail.S3BucketName,
          isMultiRegionTrail: trail.IsMultiRegionTrail,
          isLogging,
          logFileValidationEnabled: trail.LogFileValidationEnabled,
          includeGlobalServiceEvents: trail.IncludeGlobalServiceEvents,
          hasCustomEventSelectors: trail.HasCustomEventSelectors,
          kmsKeyId: trail.KmsKeyId,
          cloudWatchLogsLogGroupArn: trail.CloudWatchLogsLogGroupArn,
          snsTopicArn: trail.SnsTopicARN,
        },
      });
    }
  } catch (error) {
    console.error('Error scanning CloudTrail:', error);
  }

  return resources;
}
