variable "aws_key" {}
variable "aws_secret_key" {}
variable "aws_region" {}
variable "ami_id" {}
variable "subnet" {}
variable "vpc_security_group" {}
variable "ssh_keyname" {}
variable "ssh_key_path" {}
variable "username" {}

variable "cluster_config" {
    type="map"
    default = {
        cluster_name = "Demo"
        cluster_password = "admin"
        instance_type = "m4.2xlarge"
    }
}

provider "aws" {
    access_key = "${var.aws_key}"
    secret_key = "${var.aws_secret_key}"
    region = "${var.aws_region}"
}

resource "aws_instance" "qumulo_standalone" {
    ami = "${var.ami_id}"
    instance_type = "${var.cluster_config["instance_type"]}"
    key_name = "${var.ssh_keyname}"
    subnet_id = "${var.subnet}" 
    vpc_security_group_ids = [ "${var.vpc_security_group}"]
    tags { 
        Name = "${var.cluster_config["cluster_name"]}"
        User ="${var.username}" 
    }

    provisioner "remote-exec" { 
        inline = [
            "while [ -z \"$uuid\" ]; do sleep 1; uuid=$(qq unconfigured_nodes_list | jq --raw-output .current_node_uuid); done",
            "qq cluster_create --cluster-name ${var.cluster_config["cluster_name"]} --admin-password ${var.cluster_config["cluster_password"]} --accept-eula --node-uuids $uuid", 
            "while [ -z \"$clustername\" ]; do sleep 1; clustername=$(qq cluster_conf | jq --raw-output .cluster_name); done",
            "qq login -u admin -p ${var.cluster_config["cluster_password"]}",
            "qq set_monitoring_conf --enabled"
        ]

        connection {
            type = "ssh"
            user = "admin"
            private_key = "${file("${var.ssh_key_path}")}"
        }
    }
}

output "Private IP Address" {
    value = "${aws_instance.qumulo_standalone.private_ip}"
}