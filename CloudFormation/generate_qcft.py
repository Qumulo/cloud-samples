#!/usr/bin/env python
# Copyright (c) 2018 Qumulo, Inc. All rights reserved.
#
# NOTICE: All information and intellectual property contained herein is the
# confidential property of Qumulo, Inc. Reproduction or dissemination of the
# information or intellectual property contained herein is strictly forbidden,
# unless separate prior written permission has been obtained from Qumulo, Inc.

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
    AWSAttribute, Base64, FindInMap, GetAtt, Output, Parameter, Ref, Template,
    Join, ec2
)

# NOTE: Use only public packages.

SECURITY_GROUP_NAME = 'QumuloSecurityGroup'
KNOWLEDGE_BASE_LINK = \
    'https://care.qumulo.com/hc/en-us/sections/115003388428-QF2-IN-THE-CLOUD'

class BlockDeviceMappings(object):

    @staticmethod
    def from_specs(
            volume_count,
            pairing_ratio,
            backing_volume_type,
            backing_volume_size,
            working_volume_type,
            working_volume_size):
        assert volume_count <= 25, 'Too many volumes specified'

        working_volume_count = volume_count / (pairing_ratio + 1)
        backing_volume_count = working_volume_count * pairing_ratio
        assert volume_count == working_volume_count + backing_volume_count, \
            'Not all volumes can be used based on the pairing ratio'
        assert backing_volume_count == 0 or (
            backing_volume_size is not None and
            backing_volume_type is not None
        ), 'Backing volumes require type and size'

        if (backing_volume_size is not None):
            backing_device = ec2.EBSBlockDevice(
                VolumeType=backing_volume_type,
                VolumeSize=backing_volume_size,
                DeleteOnTermination=True,
            )

        working_device = ec2.EBSBlockDevice(
            VolumeType=working_volume_type,
            VolumeSize=working_volume_size,
            DeleteOnTermination=True,
        )

        # Create a toposphere mapping for each device
        mappings = []
        for i in range(0, volume_count):
            letter = chr(ord('b') + i)
            device_name = '/dev/xvd{}'.format(letter)
            if i < working_volume_count:
                device = working_device
            else:
                device = backing_device
            mappings.append(ec2.BlockDeviceMapping(
                DeviceName=device_name, Ebs=device
            ))

        return mappings

    @staticmethod
    def from_json(json_spec):
        # Backing disks will not be specified in AF configurations
        backing_type = json_spec.get('backing_volume_type', None)
        backing_size = json_spec.get('backing_volume_size', None)
        working_type = json_spec.get('working_volume_type')
        working_size = json_spec.get('working_volume_size')
        volume_count = json_spec.get('volume_count')
        pairing_ratio = json_spec.get('pairing_ratio')

        return BlockDeviceMappings.from_specs(
            volume_count,
            pairing_ratio,
            backing_type,
            backing_size,
            working_type,
            working_size)

class Interface(AWSAttribute):
    dictname = 'AWS::CloudFormation::Interface'

    props = {
        'ParameterGroups': ([dict], True),
        'ParameterLabels': (dict, True),
    }

def add_params(template):
    '''
    Takes a given Template object and adds parameters for user configuration
    '''
    cluster_name = Parameter(
        'ClusterName',
        Description='QF2 cluster name',
        Type='String',
    )
    template.add_parameter(cluster_name)

    admin_password = Parameter(
        'AdminPassword',
        Description='QF2 administrator account password',
        Type='String',
    )
    template.add_parameter(admin_password)

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
            'm5.12xlarge',
            'm5.24xlarge',
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

    template.add_metadata(Interface(
        ParameterGroups=[
            {
                'Label': {'default': 'Amazon EC2 Configuration'},
                'Parameters': [instance_type.title, key_name.title, ]
            },
            {
                'Label': {'default': 'Network Configuration'},
                'Parameters': [vpc_id.title, subnet_id.title, ]
            },
            {
                'Label': {'default': 'QF2 Configuration'},
                'Parameters': [cluster_name.title, admin_password.title, ]
            }
        ],
        ParameterLabels={
            instance_type.title: {'default': 'EC2 instance type'},
            key_name.title: {'default': 'SSH key-pair name'},
            vpc_id.title: {'default': 'VPC ID'},
            subnet_id.title: {'default': 'Subnet ID in the VPC'},
            cluster_name.title: {'default': 'QF2 cluster name'},
            admin_password.title: {'default': 'QF2 administrator password'}
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

def add_security_group(template):
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
            CidrIp = '0.0.0.0/0'
        ))

    # Ingress UDP ports
    for port in ['111', '2049']:
        sg_in.append(ec2.SecurityGroupRule(
            Description = 'UDP ports for NFS',
            IpProtocol = 'udp',
            FromPort = port,
            ToPort = port,
            CidrIp = '0.0.0.0/0'
        ))

    # Egress rule for all ports and protocols
    sg_out.append(ec2.SecurityGroupRule(
        Description = 'Outbound traffic',
        IpProtocol = '-1',
        FromPort = 0,
        ToPort = 0,
        CidrIp = '0.0.0.0/0'
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

def generate_cluster_script(instances):

    script = []

    script_header = [
        '#!/bin/bash\n',
        '\n',
        'set -ex\n',
        'export HOME=/home/admin\n',
        '\n',
    ]
    script += script_header

    wait_for_qfsd_on_node_one = [
        'echo Waiting for qumulo-qfsd.service start up on {}...\n'.format(
            instances[0].title),
        'while ! /opt/qumulo/cli/qq unconfigured_nodes_list > /dev/null 2>&1 ; '
            'do sleep 1 ; done\n',
        'echo qumulo-qfsd.server started on {}.\n'.format(instances[0].title),
        '\n',
    ]
    script += wait_for_qfsd_on_node_one

    for instance in instances[1:]:
        wait_for_qfsd = [
            'echo Waiting for qumulo-qfsd.service start up on {}...\n'.format(
                instance.title),
            'while ! /opt/qumulo/cli/qq '
                '--host ', GetAtt(instance.title, 'PrivateIp'),
                ' unconfigured_nodes_list > /dev/null 2>&1 ; '
            'do sleep 1 ; done\n',
            'echo qumulo-qfsd.server started on {}.\n'.format(instance.title),
            '\n',
        ]
        script += wait_for_qfsd

    wait_for_metadata_service = [
        'echo Waiting for EC2 instance metadata service start up...\n',
        'while ! curl http://169.254.169.254/latest/meta-data/instance-id > '
            '/dev/null 2>&1 ; do sleep 1 ; done\n',
        'echo EC2 instance metadata service started.\n',
        '\n',
    ]
    script += wait_for_metadata_service

    create_cluster = [
        'echo Creating QF2 cluster...\n',
        '/opt/qumulo/cli/qq cluster_create --accept-eula '
        '--cluster-name ', Ref('ClusterName'),
        ' --admin-password ', Ref('AdminPassword'),
        ' --host-instance-id '
            '$(curl http://169.254.169.254/latest/meta-data/instance-id) ',
        ' --node-ips '
            '$(curl http://169.254.169.254/latest/meta-data/local-ipv4)',
    ]

    for instance in instances[1:]:
        create_cluster += [ ' ', GetAtt(instance.title, 'PrivateIp') ]

    create_cluster += [
        '\n',
        'echo QF2 cluster created.\n',
        '\n'
    ]
    script += create_cluster

    return Base64(Join('', script))

def add_nodes(template, num_nodes, prefix, block_device_mappings):
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

    for i in range(1, num_nodes + 1):
        instance = ec2.Instance(
            '{}Node{}'.format(prefix, i),
            ImageId=FindInMap('RegionMap', Ref('AWS::Region'), 'AMI'),
            InstanceType=Ref('InstanceType'),
            KeyName=Ref('KeyName'),
            NetworkInterfaces=network_interfaces,
            BlockDeviceMappings=block_device_mappings,
        )

        instances.append(instance)

    instances[0].UserData = generate_cluster_script(instances)

    for instance in instances:
        template.add_resource(instance)

    # Create a list containing the Private IPs of all nodes.
    output_ips = []
    for instance in instances:
        output_ips.append(GetAtt(instance.title, 'PrivateIp'))

    template.add_output(Output(
        'ClusterPrivateIPs',
        Description=
            'Copy and paste this list into the QF2 Cluster Creation Screen',
        Value=Join(', ', output_ips),
    ))
    template.add_output(Output(
        'LinkToManagement',
        Description='Click to launch the QF2 Admin Console',
        Value=Join(
            '',
            ['https://', GetAtt(instances[0].title, 'PrivateIp')]),
    ))
    template.add_output(Output(
        'InstanceId',
        Description=
            'Copy and paste this instance ID into the QF2 Cluster Creation '
            'Screen.',
        Value=Ref(instances[0].title),
    ))
    template.add_output(Output(
        'QumuloKnowledgeBase',
        Description='Qumulo Knowledge Base for QF2 in public clouds',
        Value=KNOWLEDGE_BASE_LINK
    ))

def create_qumulo_cft(num_nodes, prefix, ami_id, block_device_mappings):
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
    add_params(template)
    add_ami_map(template, ami_id)
    add_security_group(template)
    add_nodes(template, num_nodes, prefix, block_device_mappings)
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

    return parser.parse_args(argv)

def main(argv):
    options = parse_args(argv)
    num_nodes = options.num_nodes
    config_json = json.load(open(options.config_file))
    cf_template = create_qumulo_cft(
        num_nodes,
        'QF2',
        options.ami_id,
        BlockDeviceMappings.from_json(config_json))
    print cf_template.to_json()

if __name__ == '__main__':
    main(sys.argv[1:])
