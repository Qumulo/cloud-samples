# Qumulo Cloud Deployment Samples
Samples for deploying Qumulo Core in AWS using popular orchestration technologies

## Terraform 
www.terraform.io  
  
qumulo_clustered.tf contains a terraform template for deploying Qumulo clusters.  Set the number of nodes in the cluster_config variable (either 1, or 4+).  A tfvars file can be used to provide the neccessary variables from your environment.  

