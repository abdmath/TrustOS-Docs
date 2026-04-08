import { EC2Client, DescribeSecurityGroupsCommand, DescribeVolumesCommand, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { ScannedResource } from '@/types';

export async function scanEC2(client: EC2Client, region: string): Promise<ScannedResource[]> {
  const resources: ScannedResource[] = [];

  // Scan Security Groups
  try {
    const sgResponse = await client.send(new DescribeSecurityGroupsCommand({}));
    for (const sg of sgResponse.SecurityGroups || []) {
      if (!sg.GroupId) continue;

      const ingressRules = (sg.IpPermissions || []).flatMap(perm => {
        const rules: Record<string, unknown>[] = [];
        for (const range of perm.IpRanges || []) {
          rules.push({
            protocol: perm.IpProtocol,
            fromPort: perm.FromPort ?? 0,
            toPort: perm.ToPort ?? 65535,
            cidrIp: range.CidrIp,
            description: range.Description,
          });
        }
        for (const range of perm.Ipv6Ranges || []) {
          rules.push({
            protocol: perm.IpProtocol,
            fromPort: perm.FromPort ?? 0,
            toPort: perm.ToPort ?? 65535,
            cidrIp: range.CidrIpv6,
            description: range.Description,
          });
        }
        return rules;
      });

      const tags = (sg.Tags || []).reduce((acc, t) => {
        if (t.Key && t.Value) acc[t.Key] = t.Value;
        return acc;
      }, {} as Record<string, string>);

      resources.push({
        arn: `arn:aws:ec2:${region}::security-group/${sg.GroupId}`,
        resourceType: 'security_group',
        service: 'EC2',
        region,
        name: sg.GroupName || sg.GroupId,
        configuration: {
          groupId: sg.GroupId,
          groupName: sg.GroupName,
          description: sg.Description,
          vpcId: sg.VpcId,
          ingressRules,
        },
        tags,
      });
    }
  } catch (error) {
    console.error('Error scanning Security Groups:', error);
  }

  // Scan EBS Volumes
  try {
    const volResponse = await client.send(new DescribeVolumesCommand({}));
    for (const vol of volResponse.Volumes || []) {
      if (!vol.VolumeId) continue;

      const tags = (vol.Tags || []).reduce((acc, t) => {
        if (t.Key && t.Value) acc[t.Key] = t.Value;
        return acc;
      }, {} as Record<string, string>);

      resources.push({
        arn: `arn:aws:ec2:${region}::volume/${vol.VolumeId}`,
        resourceType: 'ebs_volume',
        service: 'EC2',
        region,
        name: tags['Name'] || vol.VolumeId,
        configuration: {
          volumeId: vol.VolumeId,
          volumeType: vol.VolumeType,
          size: vol.Size,
          encrypted: vol.Encrypted,
          kmsKeyId: vol.KmsKeyId,
          state: vol.State,
          availabilityZone: vol.AvailabilityZone,
        },
        tags,
      });
    }
  } catch (error) {
    console.error('Error scanning EBS Volumes:', error);
  }

  // Scan EC2 Instances
  try {
    const instResponse = await client.send(new DescribeInstancesCommand({}));
    for (const reservation of instResponse.Reservations || []) {
      for (const inst of reservation.Instances || []) {
        if (!inst.InstanceId) continue;

        const tags = (inst.Tags || []).reduce((acc, t) => {
          if (t.Key && t.Value) acc[t.Key] = t.Value;
          return acc;
        }, {} as Record<string, string>);

        resources.push({
          arn: `arn:aws:ec2:${region}::instance/${inst.InstanceId}`,
          resourceType: 'ec2_instance',
          service: 'EC2',
          region,
          name: tags['Name'] || inst.InstanceId,
          configuration: {
            instanceId: inst.InstanceId,
            instanceType: inst.InstanceType,
            state: inst.State?.Name,
            publicIpAddress: inst.PublicIpAddress,
            privateIpAddress: inst.PrivateIpAddress,
            vpcId: inst.VpcId,
            subnetId: inst.SubnetId,
            securityGroups: inst.SecurityGroups?.map(sg => ({
              groupId: sg.GroupId,
              groupName: sg.GroupName,
            })),
            iamInstanceProfile: inst.IamInstanceProfile?.Arn,
            monitoring: inst.Monitoring?.State,
          },
          tags,
        });
      }
    }
  } catch (error) {
    console.error('Error scanning EC2 Instances:', error);
  }

  return resources;
}
