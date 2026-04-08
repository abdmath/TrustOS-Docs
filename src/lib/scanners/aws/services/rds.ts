import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { ScannedResource } from '@/types';

export async function scanRDS(client: RDSClient, region: string): Promise<ScannedResource[]> {
  const resources: ScannedResource[] = [];

  try {
    const response = await client.send(new DescribeDBInstancesCommand({}));
    for (const db of response.DBInstances || []) {
      if (!db.DBInstanceIdentifier || !db.DBInstanceArn) continue;

      resources.push({
        arn: db.DBInstanceArn,
        resourceType: 'rds_instance',
        service: 'RDS',
        region,
        name: db.DBInstanceIdentifier,
        configuration: {
          dbInstanceId: db.DBInstanceIdentifier,
          dbInstanceClass: db.DBInstanceClass,
          engine: db.Engine,
          engineVersion: db.EngineVersion,
          storageEncrypted: db.StorageEncrypted,
          kmsKeyId: db.KmsKeyId,
          publiclyAccessible: db.PubliclyAccessible,
          multiAZ: db.MultiAZ,
          backupRetentionPeriod: db.BackupRetentionPeriod,
          autoMinorVersionUpgrade: db.AutoMinorVersionUpgrade,
          storageType: db.StorageType,
          allocatedStorage: db.AllocatedStorage,
          dbSubnetGroup: db.DBSubnetGroup?.DBSubnetGroupName,
          vpcSecurityGroups: db.VpcSecurityGroups?.map(sg => ({
            groupId: sg.VpcSecurityGroupId,
            status: sg.Status,
          })),
          endpoint: db.Endpoint ? {
            address: db.Endpoint.Address,
            port: db.Endpoint.Port,
          } : null,
          deletionProtection: db.DeletionProtection,
          iamDatabaseAuthenticationEnabled: db.IAMDatabaseAuthenticationEnabled,
        },
      });
    }
  } catch (error) {
    console.error('Error scanning RDS:', error);
  }

  return resources;
}
