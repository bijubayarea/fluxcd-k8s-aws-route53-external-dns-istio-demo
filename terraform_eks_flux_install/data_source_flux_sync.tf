data "flux_sync" "main" {
  target_path = var.target_path
  url         = "ssh://git@github.com/${var.github_owner}/${var.repository_name}.git"
  branch      = var.branch
}

data "kubectl_file_documents" "sync" {
  content = data.flux_sync.main.content
}

locals {
  sync = [for v in data.kubectl_file_documents.sync.documents : {
    data : yamldecode(v)
    content : v
    }
  ]
}