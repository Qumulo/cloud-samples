#!/usr/bin/env python
# Copyright (c) 2018 Qumulo, Inc. All rights reserved.
#
# NOTICE: All information and intellectual property contained herein is the
# confidential property of Qumulo, Inc. Reproduction or dissemination of the
# information or intellectual property contained herein is strictly forbidden,
# unless separate prior written permission has been obtained from Qumulo, Inc.

# XXX: Sort imports and remove `pylint: disable=imports-must-be-sorted`
# The `--sort-py-imports` option for `lint/pycheck --auto-fix` may be helpful.
# pylint: disable=imports-must-be-sorted

'''
The purpose of this scipt is to generate a AWS CloudFormation Template
for QF2 that is pre-configured for a requested number of cluster nodes, and
contains the proper configuration to allow those cluster nodes to
form a cluster and serve clients. Writes the CFT to stdout.
'''

# TODO Launch CloudFormation with the completed CFT.

import argparse
import json
import sys

from troposphere import (
    AWSAttribute,
    Base64,
    Equals,
    FindInMap,
    GetAtt,
    If,
    Join,
    Not,
    Output,
    Parameter,
    Ref,
    Template,
    ec2
)

# NOTE: Use only public packages.

SECURITY_GROUP_NAME = 'QumuloSecurityGroup'
KNOWLEDGE_BASE_LINK = 'https://qf2.co/cloud-kb'
CLUSTER_NAME_PATTERN = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$'
GIBIBYTE = 1024 ** 3

class ChassisSpec(object):
    def __init__(
            self,
            volume_count,
            pairing_ratio,
            backing_volume_type,
            backing_volume_size,
            working_volume_type,
            working_volume_size):

        assert volume_count <= 25, 'Too many volumes specified'

        self.volume_count = volume_count
        self.pairing_ratio = pairing_ratio
        self.backing_volume_type = backing_volume_type
        self.backing_volume_size = backing_volume_size
        self.working_volume_type = working_volume_type
        self.working_volume_size = working_volume_size

        self.working_volume_count = self.volume_count / (self.pairing_ratio + 1)
        self.backing_volume_count = \
            self.working_volume_count * self.pairing_ratio
        assert self.volume_count == \
            self.working_volume_count + self.backing_volume_count, \
            'Not all volumes can be used based on the pairing ratio'
        assert self.backing_volume_count == 0 or (
            self.backing_volume_size is not None and
            self.backing_volume_type is not None
        ), 'Backing volumes require type and size'

        if self.backing_volume_size is not None:
            self.backing_device = ec2.EBSBlockDevice(
                VolumeType=self.backing_volume_type,
                VolumeSize=self.backing_volume_size,
                DeleteOnTermination=True,
                Encrypted=If('IsEncrypted', 'true', 'false'),
                KmsKeyId=If(
                    'HasEncryptionKey',
                    Ref('VolumesEncryptionKey'),
                    Ref('AWS::NoValue')),
            )

        self.working_device = ec2.EBSBlockDevice(
            VolumeType=self.working_volume_type,
            VolumeSize=self.working_volume_size,
            DeleteOnTermination=True,
            Encrypted=If('IsEncrypted', 'true', 'false'),
            KmsKeyId=If(
                'HasEncryptionKey',
                Ref('VolumesEncryptionKey'),
                Ref('AWS::NoValue')),
        )

    @staticmethod
    def from_json(json_spec):
        # Backing disks will not be specified in AF configurations
        backing_type = json_spec.get('backing_volume_type', None)
        backing_size = json_spec.get('backing_volume_size', None)
        working_type = json_spec.get('working_volume_type')
        working_size = json_spec.get('working_volume_size')
        volume_count = json_spec.get('volume_count')
        pairing_ratio = json_spec.get('pairing_ratio')

        return ChassisSpec(
            volume_count,
            pairing_ratio,
            backing_type,
            backing_size,
            working_type,
            working_size)

    def _device_name_from_slot_index(self, slot_index):
        letter = chr(ord('b') + slot_index)
        return '/dev/xvd{}'.format(letter)

    def get_block_device_mappings(self):
        '''Create a troposphere mapping for each device'''
        mappings = [
            ec2.BlockDeviceMapping(
                DeviceName='/dev/sda1',
                Ebs=ec2.EBSBlockDevice(
                    Encrypted=If('IsEncrypted', 'true', 'false'),
                    KmsKeyId=If(
                        'HasEncryptionKey',
                        Ref('VolumesEncryptionKey'),
                        Ref('AWS::NoValue'))))]
        for i in range(0, self.volume_count):
            device_name = self._device_name_from_slot_index(i)

            if i < self.working_volume_count:
                device = self.working_device
            else:
                device = self.backing_device

            mappings.append(ec2.BlockDeviceMapping(
                DeviceName=device_name, Ebs=device
            ))

        return mappings

    def get_slot_specs(self):
        '''Create a slot spec json object for each device'''
        slots = []
        for i in range(0, self.volume_count):
            device_name = self._device_name_from_slot_index(i)

            if i < self.working_volume_count:
                disk_role = 'working'
                disk_size = self.working_volume_size * GIBIBYTE
            else:
                disk_role = 'backing'
                disk_size = self.backing_volume_size * GIBIBYTE

            slots.append({
                'drive_bay': device_name,
                'disk_role': disk_role,
                'disk_size': disk_size,
            })

        return {'slot_specs': slots}

class Interface(AWSAttribute):
    dictname = 'AWS::CloudFormation::Interface'

    props = {
        'ParameterGroups': ([dict], True),
        'ParameterLabels': (dict, True),
    }

def add_conditions(template):
    '''
    Add IsEncrypted and HasEncryptionKey conditions to the template.
    '''
    template.add_condition(
        'IsEncrypted', Equals(Ref('VolumesEncrypted'), 'enabled'))
    template.add_condition(
        'HasEncryptionKey', Not(Equals(Ref('VolumesEncryptionKey'), '')))

def add_params(template):
    '''
    Takes a given Template object and adds parameters for user configuration
    '''
    cluster_name = Parameter(
        'ClusterName',
        Description='QF2 cluster name (2-15 alpha-numeric characters and -)',
        Type='String',
        MinLength=2,
        MaxLength=15,
        AllowedPattern=CLUSTER_NAME_PATTERN,
        ConstraintDescription=
            'Name must be an alpha-numeric string between 2 and 15 characters. '
            'Dash (-) is allowed if not the first or last character.',
    )
    template.add_parameter(cluster_name)

    key_name = Parameter(
        'KeyName',
        Description=
            'Name of an existing EC2 KeyPair to enable SSH '
            'access to the node',
        Type='AWS::EC2::KeyPair::KeyName',
    )
    template.add_parameter(key_name)

    instance_type = Parameter(
        'InstanceType',
        Description='EC2 instance type for QF2 node',
        Type='String',
        Default='m4.4xlarge',
        AllowedValues=[
            'm4.xlarge',
            'm4.2xlarge',
            'm4.4xlarge',
            'm4.10xlarge',
            'm4.16xlarge',
            'm5.xlarge',
            'm5.2xlarge',
            'm5.4xlarge',
            'm5.8xlarge',
            'm5.12xlarge',
            'm5.16xlarge',
            'm5.24xlarge',
            'c5n.xlarge',
            'c5n.2xlarge',
            'c5n.4xlarge',
            'c5n.9xlarge',
            'c5n.18xlarge',
        ],
        ConstraintDescription=
            'Must be a Qumulo supported EC2 instance type.',
    )
    template.add_parameter(instance_type)

    vpc_id = Parameter(
        'VpcId',
        Description='ID of the VPC in which to deploy QF2.',
        Type='AWS::EC2::VPC::Id',
        ConstraintDescription='Must be the ID of an existing VPC.',
    )
    template.add_parameter(vpc_id)

    subnet_id = Parameter(
        'SubnetId',
        Description='ID of the Subnet in which to deploy QF2.',
        Type='AWS::EC2::Subnet::Id',
        ConstraintDescription='Must be the ID of an existing Subnet.',
    )
    template.add_parameter(subnet_id)

    volumes_encrypted = Parameter(
        'VolumesEncrypted',
        Type='String',
        AllowedValues=['enabled', 'disabled'],
        Default='enabled')
    template.add_parameter(volumes_encrypted)

    volumes_encryption_key = Parameter(
        'VolumesEncryptionKey',
        Type='String',
        Default='',
        Description=(
            'The KMS Key to encrypt the volumes. Use either a key ID, ARN, or '
            'an Alias. Aliases must begin with alias/ followed by the name, '
            'such as alias/exampleKey. If empty, the default KMS EBS key will '
            'be used. Choosing an invalid key name will cause the instance to '
            'fail to launch.'),
        ConstraintDescription=(
            'Must be the ID, or ARN of an existing KMS key'))
    template.add_parameter(volumes_encryption_key)

    template.add_metadata(Interface(
        ParameterGroups=[
            {
                'Label': {'default': 'Amazon EC2 Configuration'},
                'Parameters': [
                    instance_type.title,
                    key_name.title,
                    volumes_encrypted.title,
                    volumes_encryption_key.title]
            },
            {
                'Label': {'default': 'Network Configuration'},
                'Parameters': [vpc_id.title, subnet_id.title, ]
            },
            {
                'Label': {'default': 'QF2 Configuration'},
                'Parameters': [cluster_name.title, ]
            }
        ],
        ParameterLabels={
            instance_type.title: {'default': 'EC2 instance type'},
            key_name.title: {'default': 'SSH key-pair name'},
            vpc_id.title: {'default': 'VPC ID'},
            subnet_id.title: {'default': 'Subnet ID in the VPC'},
            cluster_name.title: {'default': 'QF2 cluster name'},
            volumes_encrypted.title: {'default': 'Encrypt EBS volumes'},
            volumes_encryption_key.title: {
                'default': 'EBS volumes encryption key ID'}
        }
    ))

def add_ami_map(template, ami_id):
    '''
    Takes a given Template object and AMI ID then creates the Region
    to AMI ID map which is referenced by the add_nodes function.
    '''
    template.add_mapping('RegionMap', {
        'us-east-1': {'AMI': ami_id},
        'us-east-2': {'AMI': ami_id},
        'us-west-1': {'AMI': ami_id},
        'us-west-2': {'AMI': ami_id},
        'ca-central-1': {'AMI': ami_id},
        'eu-central-1': {'AMI': ami_id},
        'eu-west-1': {'AMI': ami_id},
        'eu-west-2': {'AMI': ami_id},
        'eu-west-3': {'AMI': ami_id}
    })

def add_security_group(template, sg_cidr):
    '''
    Takes a given Template object and adds properly configured AWS
    security group to enable QF2 to cluster, replicate, and serve clients.
    Ports enabled by default:
    TCP 21, 80, 111, 443, 445, 2049, 3712, 8000
    UDP 111, 2049
    All traffic is allowed between members of the security group for clustering.
    '''
    sg_in = []
    sg_out = []

    # Ingress TCP ports
    for port in ['21', '80', '111', '443', '445', '2049', '3712', '8000']:
        sg_in.append(ec2.SecurityGroupRule(
            Description =
                'TCP ports for NFS, SMB, FTP, Management, and Replication',
            IpProtocol = 'tcp',
            FromPort = port,
            ToPort = port,
            CidrIp = sg_cidr
        ))

    # Ingress UDP ports
    for port in ['111', '2049']:
        sg_in.append(ec2.SecurityGroupRule(
            Description = 'UDP ports for NFS',
            IpProtocol = 'udp',
            FromPort = port,
            ToPort = port,
            CidrIp = sg_cidr
        ))

    # Egress rule for all ports and protocols
    sg_out.append(ec2.SecurityGroupRule(
        Description = 'Outbound traffic',
        IpProtocol = '-1',
        FromPort = 0,
        ToPort = 0,
        CidrIp = sg_cidr
    ))

    template.add_resource(ec2.SecurityGroup(
        SECURITY_GROUP_NAME,
        GroupDescription =
            'Enable ports for NFS/SMB/FTP, Management, Replication, and '
            'Clustering.',
        SecurityGroupIngress = sg_in,
        SecurityGroupEgress = sg_out,
        VpcId = Ref('VpcId')
    ))

    # Self referencing security rules need to be added after the group is
    # created.  This rule is enabling all traffic between members of the
    # security group for clustering.
    template.add_resource(ec2.SecurityGroupIngress(
        'QumuloSecurityGroupNodeRule',
        DependsOn = SECURITY_GROUP_NAME,
        Description = 'Qumulo Internode Communication',
        GroupId = Ref(SECURITY_GROUP_NAME),
        IpProtocol = '-1',
        FromPort = 0,
        ToPort = 0,
        SourceSecurityGroupId = Ref(SECURITY_GROUP_NAME)
    ))

def format_slot_specs(slot_specs_json):
    return json.dumps(slot_specs_json, indent=4).split('\n')

def generate_node1_user_data(
        instances, chassis_spec, get_ip_ref=None, cluster_name_ref=None):

    if get_ip_ref is None:
        get_ip_ref = lambda instance_name: GetAtt(instance_name, 'PrivateIp')

    if cluster_name_ref is None:
        cluster_name_ref = Ref('ClusterName')

    user_data = ['{', '"spec_info": ']
    user_data += format_slot_specs(chassis_spec.get_slot_specs())
    user_data[-1] += ','

    user_data_node_ips = ['"node_ips": [']

    for instance in instances[1:]:
        ip = get_ip_ref(instance.title)
        user_data_node_ips += ['"', ip, '", ']

    user_data_node_ips[-1] = '"],'

    user_data += user_data_node_ips

    user_data += ['"cluster_name": "', cluster_name_ref, '" }']

    return user_data

def generate_other_nodes_user_data(chassis_spec):
    user_data = [
        '{',
        '"spec_info": ',
    ]

    user_data += format_slot_specs(chassis_spec.get_slot_specs())
    user_data.append('}')

    return user_data

def add_nodes(template, num_nodes, prefix, chassis_spec):
    '''
    Takes a given Template object, an count of nodes to create, and a name to
    prefix all EC2 instances with. EC2 instances will be created with the
    naming structure of Prefix + Qumulo + NodeNumber.
    '''
    instances = []

    network_interfaces = [
        ec2.NetworkInterfaceProperty(
            AssociatePublicIpAddress=False,
            GroupSet=[Ref(SECURITY_GROUP_NAME)],
            DeviceIndex=0,
            DeleteOnTermination=True,
            SubnetId=Ref('SubnetId'),
        )
    ]

    block_device_mappings = chassis_spec.get_block_device_mappings()
    for i in range(1, num_nodes + 1):
        instance = ec2.Instance(
            '{}Node{}'.format(prefix, i),
            ImageId=FindInMap('RegionMap', Ref('AWS::Region'), 'AMI'),
            InstanceType=Ref('InstanceType'),
            KeyName=Ref('KeyName'),
            NetworkInterfaces=network_interfaces,
            BlockDeviceMappings=block_device_mappings,
            EbsOptimized=True,
        )

        instances.append(instance)

    instances[0].UserData = Base64(
        Join('', generate_node1_user_data(instances, chassis_spec)))

    for instance in instances[1:]:
        instance.UserData = Base64(
            Join('', generate_other_nodes_user_data(chassis_spec)))

    for instance in instances:
        template.add_resource(instance)

    # Create a list containing the Private IPs of all nodes.
    output_ips = []
    for instance in instances:
        output_ips.append(GetAtt(instance.title, 'PrivateIp'))

    template.add_output(Output(
        'ClusterPrivateIPs',
        Description=
            'List of the private IPs of the nodes in your QF2 Cluster',
        Value=Join(', ', output_ips),
    ))
    template.add_output(Output(
        'TemporaryPassword',
        Description=
            'Temporary admin password for your QF2 cluster '
                '(exclude quotes, matches node1 instance ID).',
        Value=Join('', ['"', Ref(instances[0].title), '"'])
    ))
    template.add_output(Output(
        'LinkToManagement',
        Description='Use to launch the QF2 Admin Console',
        Value=Join(
            '',
            ['https://', GetAtt(instances[0].title, 'PrivateIp')]),
    ))
    template.add_output(Output(
        'QumuloKnowledgeBase',
        Description='Qumulo Knowledge Base for QF2 in public clouds',
        Value=KNOWLEDGE_BASE_LINK
    ))

def create_qumulo_cft(num_nodes, prefix, ami_id, chassis_spec, sg_cidr):
    '''
    Takes a count of nodes to create, a prefix for node names, and an AMI ID.
    This function will return a completed Template object fully configured with
    the number of nodes requested.
    '''
    template = Template()
    template.add_description(
        'QF2 for AWS has the highest performance of any file storage system '
        'in the public cloud and a complete set of enterprise features, such '
        'as support for SMB, real-time visibility into the storage system, '
        'directory-based capacity quotas, and snapshots.')
    add_conditions(template)
    add_params(template)
    add_ami_map(template, ami_id)
    add_security_group(template, sg_cidr)
    add_nodes(template, num_nodes, prefix, chassis_spec)
    return template

def parse_args(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=__doc__)

    parser.add_argument(
        '--num-nodes',
        type=int,
        help='Number of nodes in the cluster',
        default=4)

    parser.add_argument(
        '--config-file',
        type=str,
        required=True,
        help='Config file path specifying volume configuration')

    parser.add_argument(
        '--ami-id',
        type=str,
        required=True,
        help='AMI ID in deployment region')

    parser.add_argument(
        '--sg-cidr',
        type=str,
        default='0.0.0.0/0',
        help='Ingress/Egress CIDR for security group')

    return parser.parse_args(argv)

def main(argv):
    options = parse_args(argv)
    num_nodes = options.num_nodes

    with open(options.config_file) as json_file:
        json_spec = json.load(json_file)

    chassis_spec = ChassisSpec.from_json(json_spec)
    cf_template = create_qumulo_cft(
        num_nodes, 'QF2', options.ami_id, chassis_spec, options.sg_cidr)
    print cf_template.to_json()

if __name__ == '__main__':
    main(sys.argv[1:])
