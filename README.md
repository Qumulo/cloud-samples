# Qumulo Cloud Deployment Samples
Samples for deploying Qumulo Core in AWS using popular orchestration
technologies. Right now we have a script to generate a custom AWS
CloudFormation template but please open an issue or PR and we'll add your
favorite orchestration technology.

## CloudFormation
https://aws.amazon.com/cloudformation/

`generate-qumulo-cloudformation-template.py` is a python script that generates
an AWS CloudFormation template (CFT) with the desired number of nodes and
instance names. The CFT that is generated will contain a preconfigured AWS
Security Group that enables the cluster to serve clients as well as opens
ports for management, replication, and clustering.
