#variable "project_id" {
#  description = "project id"
#  type        = string
#}
variable "region" {
  description = "AWS Region"
  type        = string
  default     = "us-west-2"
}

variable "github_token" {
  description = "token for github"
  type        = string
}

variable "github_owner" {
  description = "github owner"
  type        = string
}

variable "repository_name" {
  description = "repository name"
  type        = string
}

variable "repository_visibility" {
  description = "visibility of github repository"
  type        = string
  default     = "private"
}

variable "branch" {
  description = "branch"
  type        = string
  default     = "main"
}

# flux sync path location
variable "target_path" {
  type        = string
  description = "Relative path to the Git repository root where the sync manifests are committed."
}

variable "flux_namespace" {
  type        = string
  default     = "flux-system"
  description = "The flux namespace"
}

#variable "cluster_name" {
#  type        = string
#  description = "cluster name"
#  default     = data.aws_eks_cluster.cluster.name
#}

#variable "cluster_region" {
#  type        = string
#  description = "cluster region"
#  default     = data.terraform_remote_state.eks.outputs.region
#}

variable "use_private_endpoint" {
  type        = bool
  description = "Connect on the private EKS cluster endpoint"
  default     = true
}

variable "github_deploy_key_title" {
  type        = string
  description = "Name of github deploy key"
}