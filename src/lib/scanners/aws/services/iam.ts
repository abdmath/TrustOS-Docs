import { IAMClient, ListUsersCommand, ListMFADevicesCommand, ListAccessKeysCommand, GetAccessKeyLastUsedCommand, ListAttachedUserPoliciesCommand } from '@aws-sdk/client-iam';
import { ScannedResource } from '@/types';

export async function scanIAM(client: IAMClient): Promise<ScannedResource[]> {
  const resources: ScannedResource[] = [];

  try {
    const usersResponse = await client.send(new ListUsersCommand({}));
    const users = usersResponse.Users || [];

    for (const user of users) {
      if (!user.UserName || !user.Arn) continue;

      const config: Record<string, unknown> = {
        userName: user.UserName,
        userId: user.UserId,
        createDate: user.CreateDate?.toISOString(),
        passwordLastUsed: user.PasswordLastUsed?.toISOString(),
      };

      // Check MFA
      try {
        const mfaResponse = await client.send(new ListMFADevicesCommand({ UserName: user.UserName }));
        config.mfaEnabled = (mfaResponse.MFADevices || []).length > 0;
        config.mfaDevices = mfaResponse.MFADevices?.map(d => ({
          serialNumber: d.SerialNumber,
          enableDate: d.EnableDate?.toISOString(),
        }));
      } catch {
        config.mfaEnabled = false;
      }

      // Check Access Keys
      try {
        const keysResponse = await client.send(new ListAccessKeysCommand({ UserName: user.UserName }));
        const accessKeys = [];
        for (const key of keysResponse.AccessKeyMetadata || []) {
          let lastUsedDate: string | undefined;
          try {
            const lastUsed = await client.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId }));
            lastUsedDate = lastUsed.AccessKeyLastUsed?.LastUsedDate?.toISOString();
          } catch {
            // ignore
          }
          accessKeys.push({
            accessKeyId: key.AccessKeyId,
            status: key.Status,
            createDate: key.CreateDate?.toISOString(),
            lastUsedDate,
          });
        }
        config.accessKeys = accessKeys;
      } catch {
        config.accessKeys = [];
      }

      // Check Attached Policies
      try {
        const policiesResponse = await client.send(new ListAttachedUserPoliciesCommand({ UserName: user.UserName }));
        config.attachedPolicies = (policiesResponse.AttachedPolicies || []).map(p => ({
          policyName: p.PolicyName,
          policyArn: p.PolicyArn,
        }));
      } catch {
        config.attachedPolicies = [];
      }

      config.isRoot = user.UserName === 'root' || user.Arn?.endsWith(':root');

      resources.push({
        arn: user.Arn,
        resourceType: 'iam_user',
        service: 'IAM',
        region: 'global',
        name: user.UserName,
        configuration: config,
      });
    }
  } catch (error) {
    console.error('Error scanning IAM:', error);
  }

  return resources;
}
