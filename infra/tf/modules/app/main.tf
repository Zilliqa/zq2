variable "name" {
  type = string
    nullable = false
}

variable "image" {
    type = string
    nullable = false
}

variable "args" {
    type = list(string)
    default = null
}

variable "env" {
    type = list(tuple([string, string]))
    default = []
}

variable "static_ip_name" {
    type = string
    nullable = false
}

variable "domain" {
    type = string
    nullable = false
}

resource "kubernetes_deployment" "this" {
  metadata {
    name   = var.name
    labels = { "app" = var.name }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app" = var.name }
    }
    template {
      metadata {
        labels = { "app" = var.name }
      }
      spec {
        container {
          name  = var.name
          image = var.image
          image_pull_policy = "Always"
          args  = var.args
          dynamic "env" {
            for_each = var.env
            content {
              name = env.value[0]
              value = env.value[1]
            }
          }
          security_context {
            allow_privilege_escalation = false
            capabilities {
              drop = ["NET_RAW"]
            }
          }
        }
        security_context {
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }
        toleration {
          effect   = "NoSchedule"
          key      = "kubernetes.io/arch"
          operator = "Equal"
          value    = "amd64"
        }
      }
    }
  }
}

resource "kubernetes_service" "this" {
  metadata {
    name        = var.name
    labels      = { "app" = var.name }
    annotations = { "cloud.google.com/neg" = jsonencode({ ingress = true }) }
  }

  spec {
    port {
      port = 80
    }
    selector = { "app" = var.name }
  }
}

resource "kubernetes_ingress_v1" "this" {
  metadata {
    name = var.name

    annotations = {
      "kubernetes.io/ingress.class"                 = "gce"
      "kubernetes.io/ingress.global-static-ip-name" = var.static_ip_name
      "networking.gke.io/managed-certificates"      = kubernetes_manifest.managed_certificate.manifest.metadata.name
    }
  }

  spec {
    rule {
      host = var.domain

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service.this.metadata[0].name

              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_manifest" "managed_certificate" {
  manifest = {
    apiVersion = "networking.gke.io/v1"
    kind       = "ManagedCertificate"
    metadata = {
      name      = var.name
      namespace = "default"
    }
    spec = {
      domains = [var.domain]
    }
  }
}
