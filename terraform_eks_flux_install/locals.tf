# Cluster name
locals {
    cluster_name    = data.aws_eks_cluster.cluster.name
}

# Cluster name
locals{
    cluster_region  = data.terraform_remote_state.eks.outputs.region
}
