terraform {
  required_version = ">= 0.13"
  #required_version = ">= 0.15"

  required_providers {
    github = {
      source  = "integrations/github"
      version = ">= 4.5.2"
      #version = "4.12.2"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0.2"
      #version = "2.3.2"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = ">= 1.10.0"
      #version =  "1.11.2"
    }
    flux = {
      source  = "fluxcd/flux"
      version = ">= 0.0.13"
      #version = "0.2.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "3.1.0"
    }
  }
}

# Flux
provider "flux" {}


# Retrieve AWS cluster information
provider "aws" {
  region                   = data.terraform_remote_state.eks.outputs.region
  shared_credentials_files = ["~/.aws/credentials"]
  profile                  = "vscode-user"
}


provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = ["eks", "get-token", "--cluster-name",local.cluster_name]
  }
}

provider "kubectl" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  load_config_file       = false

    exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", local.cluster_name]
  }

}

