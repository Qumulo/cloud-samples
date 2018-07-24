from troposphere import FindInMap, GetAtt, Output
from troposphere import Parameter, Ref, Template, Join
import troposphere.ec2 as ec2

# The purpose of this scipt is to generate a AWS CloudFormation Template
# for QF2 that is pre-configured for a requested number of cluster nodes, and
# contains the proper configuration to allow those cluster nodes to
# form a cluster and serve clients.
# 
# TODO Launch CloudFormation with the completed CFT. 


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

# add_amimap() takes a given Template object and AMI ID then creates the Region to AMI ID map 
# which is referenced by the add_nodes function. 
def add_amimap(t, amiid):
    t.add_mapping('RegionMap', {
        "us-east-1":      {"AMI": amiid},
        "us-east-2":      {"AMI": "US-EAST-1-AMI-CLONE"},
        "us-west-1":      {"AMI": "US-EAST-1-AMI-CLONE"},
        "us-west-2":      {"AMI": "US-EAST-1-AMI-CLONE"},
        "ca-central-1":   {"AMI": "US-EAST-1-AMI-CLONE"},
        "eu-central-1":   {"AMI": "US-EAST-1-AMI-CLONE"},
        "eu-west-1":      {"AMI": "US-EAST-1-AMI-CLONE"},
        "eu-west-2":      {"AMI": "US-EAST-1-AMI-CLONE"},
        "eu-west-3":      {"AMI": "US-EAST-1-AMI-CLONE"}
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

    #Ingress TCP ports
    for port in ['21', '80', '111', '443', '445', '2049', '3712', '8000']:
        sg_in.append(ec2.SecurityGroupRule(
                Description = "TCP ports for NFS, SMB, FTP, Management, and Replication",
                IpProtocol = 'tcp',
                FromPort = port,
                ToPort = port,
                CidrIp = '0.0.0.0/0'
            )
        )

    #Ingress UDP ports
    for port in ['111', '2049']:
        sg_in.append(ec2.SecurityGroupRule(
                Description = "UDP ports for NFS",
                IpProtocol = 'udp',
                FromPort = port,
                ToPort = port,
                CidrIp = '0.0.0.0/0'
            )
        )
    
    #Egress rule for all ports and protocols
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
        node_name = prefix + "Node" + str((x + 1))
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
        "ClusterPrivateIPs",
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

# create_qumulo_cft() takes a count of nodes to create, a prefix for node names, and an AMI ID.
# This function will return a completed Template object fully configured
# with the number of nodes requested.
def create_qumulo_cft(nodes, prefix, amiid):
    t = Template()
    t.add_description("QF2 for AWS has the highest performance of any file storage "
        "system in the public cloud and a complete set of enterprise features, such "
        "as support for SMB, real-time visibility into the storage system, "
        "directory-based capacity quotas, and snapshots.")
    add_params(t)
    add_amimap(t, amiid)
    add_secgroup(t)
    add_nodes(t, nodes, prefix)
    return t

# write_listing_cfts() takes in a prefix to be used for node/file naming, a suffix for the file
# name, and an AMI ID for the us-east-1 AMI ID that will be cloned to other regions when the 
# listing is active. Initially this will create three CFTs: 4, 6, and 10 node clusters.
def write_listing_cfts(prefix, suffix, amiid):
    qcft4 = create_qumulo_cft(4, prefix, amiid)
    qcft6 = create_qumulo_cft(6, prefix, amiid)
    qcft10 = create_qumulo_cft(10, prefix, amiid)

    f_four_node = open(prefix + "-4Node-" + suffix + ".json", "w")
    f_four_node.write(qcft4.to_json())
    f_four_node.close()

    f_six_node = open(prefix + "-6Node-" + suffix + ".json", "w")
    f_six_node.write(qcft6.to_json())
    f_six_node.close()

    f_ten_node = open(prefix + "-10Node-" + suffix + ".json", "w")
    f_ten_node.write(qcft10.to_json())
    f_ten_node.close()

if __name__ == '__main__':
    write_listing_cfts("QF2", "5TB", "AMI-ID-US-EAST-1")
    write_listing_cfts("QF2", "20TB", "AMI-ID-US-EAST-1")






