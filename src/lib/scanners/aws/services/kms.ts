import { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } from '@aws-sdk/client-kms';
import { ScannedResource } from '@/types';

export async function scanKMS(client: KMSClient, region: string): Promise<ScannedResource[]> {
  const resources: ScannedResource[] = [];

  try {
    const response = await client.send(new ListKeysCommand({}));
    for (const key of response.Keys || []) {
      if (!key.KeyId || !key.KeyArn) continue;

      let keyDetails: Record<string, unknown> = {};
      try {
        const descResponse = await client.send(new DescribeKeyCommand({ KeyId: key.KeyId }));
        const meta = descResponse.KeyMetadata;
        if (meta?.KeyManager === 'AWS') continue; // Skip AWS-managed keys

        keyDetails = {
          keyId: meta?.KeyId,
          keyState: meta?.KeyState,
          keyUsage: meta?.KeyUsage,
          keyManager: meta?.KeyManager,
          description: meta?.Description,
          creationDate: meta?.CreationDate?.toISOString(),
          origin: meta?.Origin,
        };
      } catch {
        continue;
      }

      let rotationEnabled = false;
      try {
        const rotResponse = await client.send(new GetKeyRotationStatusCommand({ KeyId: key.KeyId }));
        rotationEnabled = rotResponse.KeyRotationEnabled ?? false;
      } catch {
        // ignore
      }

      resources.push({
        arn: key.KeyArn,
        resourceType: 'kms_key',
        service: 'KMS',
        region,
        name: (keyDetails.description as string) || key.KeyId,
        configuration: {
          ...keyDetails,
          keyRotationEnabled: rotationEnabled,
        },
      });
    }
  } catch (error) {
    console.error('Error scanning KMS:', error);
  }

  return resources;
}
