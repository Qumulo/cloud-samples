/**
 * This file defines four clustered nodes of QF2.
 *
 * To use this file, you'll need to provide values for some of the variables
 * below. You can either set their values on the command line using the var
 * flag:
 *
 *     terraform apply -var aws_subnet_id=subnet-fakeid ...
 *
 * or by using a .tfvars file. See this documentation for more:
 * https://www.terraform.io/intro/getting-started/variables.html
 *
 * In addition to specifying the required variables, you'll also need your
 * environment to be configured with some AWS API credentials. Terraform's AWS
 * provider plugin can use the same ~/.aws/credentials file that's used by the
 * AWS CLI tool and boto3.
 */

// Specify the region in which you want to run QF2.
variable aws_region { type = "string" }

// Specify the subnet in which you want to run QF2.
variable aws_subnet_id { type = "string" }

// Specify the admin password you want to set for you QF2 cluster.
variable cluster_admin_password { type = "string" }

// Specify the name of the SSH key pair that you want to launch your EC2
// instances with. This has to be the name of a key pair that you've already
// uploaded to AWS.
variable ssh_key_name { type = "string" }

// Specify the local path to the private key or .pem for the key pair that
// you've chosen above.
variable ssh_key_path { type = "string" }

// Optionally, specify the AMI id for the version of QF2 that you want to
// launch.
variable ami_id {
  type = "string"
  default = ""
}

// Optionally, set a username that will be used to tag the provisioned EC2
// instances.
variable username {
  type = "string"
  default = ""
}

// Optionally, set the cluster name, size, and underlying EC2 instance type.
variable "cluster_config" {
  type = "map"
  default = {
    cluster_name = "Qumulo"
    node_count = 4
    instance_type = "m4.16xlarge"
  }
}

provider "aws" {
  region = "${var.aws_region}"
}

// Looks up the metadata for the specified subnet from above.
data "aws_subnet" "selected" {
  id = "${var.aws_subnet_id}"
}

// This security group allows all traffic to and from the nodes. You can modify
// the ingress and egress sections below to change that. Documentation:
// https://www.terraform.io/docs/providers/aws/r/security_group.html
resource "aws_security_group" "allow_all" {
  name_prefix = "se_demo"
  description = "Allows all traffic for a sales demo"
  vpc_id = "${data.aws_subnet.selected.vpc_id}"

  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

// Find the latest AMI owned by Qumulo's engineering AWS account.
data "aws_ami" "latest" {
  most_recent = true
  owners = [ "343459513285" ] // This is the Qumulo Engineering account id
  name_regex = "^Qumulo-Cloud.*-release-.*$"
}

// If you specified a specific AMI using `-var ami_id=$AMI_ID` when running this
// template, we'll use that one instead of the latest one.
locals {
  ami_id = "${ var.ami_id != "" ? var.ami_id : data.aws_ami.latest.id }"
}

// Create the nodes and ensure that QF2 comes up on each.
resource "aws_instance" "node" {
  count = "${var.cluster_config["node_count"]}"
  ami = "${local.ami_id}"
  instance_type = "${var.cluster_config["instance_type"]}"
  key_name = "${var.ssh_key_name}"
  subnet_id = "${data.aws_subnet.selected.id}"
  vpc_security_group_ids = [ "${aws_security_group.allow_all.id}" ]
  tags {
    Name = "${var.cluster_config["cluster_name"]} ${count.index + 1}"
    User = "${var.username}"
  }

  // Don't consider a node as up until qq is up
  provisioner "remote-exec" {
    inline = [ "until qq version; do sleep 1; done;" ]
    connection = {
      type = "ssh"
      user = "admin"
      private_key = "${file("${var.ssh_key_path}")}"
    }
  }
}

// This block is used to decide if we have to SSH into a public or private IP
// when clustering our nodes.
locals {
  public_ip = "${aws_instance.node.0.public_ip}"
  private_ip ="${aws_instance.node.0.private_ip}"
  lead_node_ip = "${ local.public_ip != "" ? local.public_ip : local.private_ip }"
}

// Cluster the nodes.
resource "null_resource" "cluster_nodes" {
  triggers {
    nodes = "${join(",", aws_instance.node.*.id)}"
  }

  provisioner "remote-exec" {
    inline = [ <<SCRIPT
# Cluster the nodes
qq cluster_create --accept-eula \
  --cluster-name ${var.cluster_config["cluster_name"]} \
  --admin-password ${var.cluster_admin_password} \
  --host-instance-id ${aws_instance.node.0.id} \
  --node-ips ${join(" ", aws_instance.node.*.private_ip)}
# And wait for clustering to complete
until qq node_state_get | jq -e '.state == "ACTIVE"'; do sleep 1; done
SCRIPT
    ]

    connection {
      type = "ssh"
      host = "${local.lead_node_ip}"
      user = "admin"
      private_key = "${file("${var.ssh_key_path}")}"
    }
  }
}

output "Private IP Addresses" {
  value = ["${aws_instance.node.*.private_ip}"]
}
output "Public IP Addresses" {
  value = ["${aws_instance.node.*.public_ip}"]
}
