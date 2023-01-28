locals {
  known_hosts = "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg="
}

resource "tls_private_key" "github_deploy_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "kubernetes_secret" "main" {
  depends_on = [kubectl_manifest.install]

  metadata {
    name      = data.flux_sync.main.secret
    namespace = data.flux_sync.main.namespace
  }

  data = {
    known_hosts    = local.known_hosts
    identity       = tls_private_key.github_deploy_key.private_key_pem
    "identity.pub" = tls_private_key.github_deploy_key.public_key_openssh
  }
}

# Github
provider "github" {
  token         = var.github_token
  owner         = var.github_owner
}

## data source allows you to read files within a GitHub repository
#data "github_repository" "main" {
#  full_name     = "${var.github_owner}/${var.repository_name}"
#  visibility    = var.repository_visibility
#}

# Resource to manage Github Repository
resource "github_repository" "main" {
  name       = var.repository_name
  visibility = var.repository_visibility
  auto_init  = true
}

# Default "branch" of github repo
resource "github_branch_default" "main" {
  repository = github_repository.main.name
  branch     = var.branch
}


resource "github_repository_file" "install" {
  repository          = github_repository.main.name
  file                = data.flux_install.main.path
  content             = data.flux_install.main.content
  branch              = var.branch
  overwrite_on_create = true
}

resource "github_repository_file" "sync" {
  repository          = github_repository.main.name
  file                = data.flux_sync.main.path
  content             = data.flux_sync.main.content
  branch              = var.branch
  overwrite_on_create = true
}

resource "github_repository_file" "kustomize" {
  repository          = github_repository.main.name
  file                = data.flux_sync.main.kustomize_path
  content             = data.flux_sync.main.kustomize_content
  branch              = var.branch
  overwrite_on_create = true
}

# For flux to fetch source
resource "github_repository_deploy_key" "flux" {
  title      = var.github_deploy_key_title
  repository = github_repository.main.name
  key        = tls_private_key.github_deploy_key.public_key_openssh
  read_only  = true
}