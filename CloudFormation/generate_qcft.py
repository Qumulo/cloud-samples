from troposphere import FindInMap, GetAtt, Output
from troposphere import Parameter, Ref, Template, Join
import troposphere.ec2 as ec2

# add_params() takes a given Template object and adds parameters for SSH keys,
# allowed AWS node types, VPC, and Subnet ID
def add_params(t):
    t.add_parameter(Parameter(
        "KeyName",
        Description="Name of an existing EC2 KeyPair to enable SSH "
                    "access to the node",
        Type="AWS::EC2::KeyPair::KeyName",
    ))

    t.add_parameter(Parameter(
            "InstanceType",
            Description="EC2 instance type for QF2 node",
            Type="String",
            Default="m4.4xlarge",
            AllowedValues=[
                    "t2.medium",
                    "m4.xlarge",
                    "m4.2xlarge",
                    "m4.4xlarge",
                    "m4.10xlarge",
                    "m4.16xlarge"
                ],
            ConstraintDescription="Must be a Qumulo supported EC2 instance type.",
    ))

    t.add_parameter(Parameter(
            "VpcId",
            Description="ID of the VPC in which to deploy QF2.",
            Type="AWS::EC2::VPC::Id",
            ConstraintDescription="Must be the ID of an existing VPC.",
    ))

    t.add_parameter(Parameter(
            "SubnetId",
            Description="ID of the Subnet in which to deploy QF2.",
            Type="AWS::EC2::Subnet::Id",
            ConstraintDescription="Must be the ID of an existing Subnet.",
    ))

# add_amimap() takes a given Template object and adds the Region to AMI ID map 
# which is referenced by the add_nodes function. This may ultimately be replaced 
# by being passed the correct AMI ID directly to add_nodes()
#
# TODO Either switch to direct input of AMI ID and AWS region to add_nodes(), or
# populate this map with the full supported region list and current AMI IDs
def add_amimap(t):
    t.add_mapping('RegionMap', {
        "us-east-1":      {"AMI": "ami-REPLACE"},
        "us-west-1":      {"AMI": "ami-071618db4dece32ec"},
        "us-west-2":      {"AMI": "ami-0a1e10d1617be698d"},
        "eu-west-1":      {"AMI": "ami-REPLACE"},
        "sa-east-1":      {"AMI": "ami-REPLACE"},
        "ap-southeast-1": {"AMI": "ami-REPLACE"},
        "ap-northeast-1": {"AMI": "ami-REPLACE"}
    })

# add_secgroup() takes a given Template object and adds properly configured AWS
# security group to enable QF2 to cluster, replicate, and serve clients.
# Ports enabled by default:
# TCP 21, 80, 111, 443, 445, 2049, 3712, 8000
# UDP 111, 2049
# All traffic is allowed between members of the security group for clustering.
def add_secgroup(t):
    sg_in = []
    sg_out = []

    for port in ['21', '80', '111', '443', '445', '2049', '3712', '8000']:
        sg_in.append(ec2.SecurityGroupRule(
                Description = "TCP ports for NFS, SMB, FTP, Management, and Replication",
                IpProtocol = 'tcp',
                FromPort = port,
                ToPort = port,
                CidrIp = '0.0.0.0/0'
            )
        )
    for port in ['111', '2049']:
        sg_in.append(ec2.SecurityGroupRule(
                Description = "UDP ports for NFS",
                IpProtocol = 'udp',
                FromPort = port,
                ToPort = port,
                CidrIp = '0.0.0.0/0'
            )
        )
    
    sg_out.append(ec2.SecurityGroupRule(
        Description = "Outbound traffic",
        IpProtocol = '-1',
        FromPort = 0,
        ToPort = 0,
        CidrIp = '0.0.0.0/0'
        )
    )

    t.add_resource(ec2.SecurityGroup(
        "QumuloSecurityGroup",
        GroupDescription = "Enable ports for NFS/SMB/FTP, Management, Replication, and Clustering.",
        SecurityGroupIngress = sg_in,
        SecurityGroupEgress = sg_out,
        VpcId = Ref("VpcId")
    ))

    # Self referencing security rules need to be added after the group is created. 
    # This rule is enabling all traffic between members of the security group for 
    # clustering.
    t.add_resource(ec2.SecurityGroupIngress(
        "QumuloSecurityGroupNodeRule",
        DependsOn = "QumuloSecurityGroup",
        Description = "Qumulo Internode Communication",
        GroupId = Ref("QumuloSecurityGroup"),
        IpProtocol = '-1',
        FromPort = 0,
        ToPort = 0,
        SourceSecurityGroupId = Ref("QumuloSecurityGroup")
    ))

# add_nodes() takes a given Template object, an count of nodes to create, and
# a name to prefix all EC2 instances with. EC2 instances will be created with the
# naming structure of Prefix + Qumulo + NodeNumber.
def add_nodes(t, nodes, prefix):
    nodes_list = []

    for x in range(0, nodes):
        node_name = prefix + "Qumulo" + str((x + 1))
        t.add_resource(
            ec2.Instance(
                node_name,
                ImageId = FindInMap("RegionMap", Ref("AWS::Region"), "AMI"),
                InstanceType = Ref("InstanceType"),
                KeyName = Ref("KeyName"),
                NetworkInterfaces = [
                    ec2.NetworkInterfaceProperty(
                        AssociatePublicIpAddress = False,
                        GroupSet = [Ref("QumuloSecurityGroup")],
                        DeviceIndex = 0,
                        DeleteOnTermination = True,
                        SubnetId = Ref("SubnetId"),
                    )
                ]
            )
        )
        nodes_list.append(node_name)
    
    # Create a list containing the Private IPs of all nodes.
    output_ips = []
    for i in nodes_list:
        output_ips.append(GetAtt(i, "PrivateIp"))

    t.add_output(Output(
        "NodePrivateIPs",
        Description="Copy and paste this list into the QF2 Cluster Creation Screen",
        Value=Join(", ", output_ips),
    ))
    t.add_output(Output(
        "LinkToManagement",
        Description="Click to launch the QF2 Admin Console",
        Value=Join("", ["https://",GetAtt(nodes_list[0], "PrivateIp")]),
    ))
    t.add_output(Output(
        "InstanceId",
        Description="Copy and paste this instance ID into the QF2 Cluster Creation Screen.",
        Value=Ref(prefix + "Qumulo1"),
    ))

# create_qumulo_cft() takes a count of nodes to create as well as a prefix for 
# node names. This function will return a completed Template object fully configured
# with the number of nodes requested.
def create_qumulo_cft(nodes, prefix):
    t = Template()
    t.add_description("QF2 for AWS has the highest performance of any file storage "
        "system in the public cloud and a complete set of enterprise features, such "
        "as support for SMB, real-time visibility into the storage system, "
        "directory-based capacity quotas, and snapshots.")
    add_params(t)
    add_amimap(t)
    add_secgroup(t)
    add_nodes(t, nodes, prefix)
    return t

qcft = create_qumulo_cft(9, "Quetzalqoatl")
print(qcft.to_json())

#TODO Launch CloudFormation with the completed CFT.