# collect the information related to the bucket
data "google_storage_bucket" "default" {
  name = var.gcs_bucket_name
}

# reserve IP address
resource "google_compute_global_address" "default" {
  project = var.project_id
  name    = format("%s-ip", var.name)
}

# backend bucket with CDN policy with default ttl settings
resource "google_compute_backend_bucket" "default" {
  name        = format("%s-backend", var.name)
  bucket_name = data.google_storage_bucket.default.name
  enable_cdn  = true
  cdn_policy {
    cache_mode        = "CACHE_ALL_STATIC"
    client_ttl        = 3600
    default_ttl       = 3600
    max_ttl           = 86400
    negative_caching  = true
    serve_while_stale = 86400
    bypass_cache_on_request_headers {
       header_name = "X-z-cdn-bypass"
    }
  }
  project = var.project_id
}

# url map https
resource "google_compute_url_map" "default" {
  name            = format("%s-lb-https", var.name)
  default_service = google_compute_backend_bucket.default.id
  project         = var.project_id
}

# url map http
# Partial HTTP load balancer redirects to HTTPS
resource "google_compute_url_map" "default_http" {
  name    = format("%s-lb-static-http-redirect", var.name)
  project = var.project_id
  default_url_redirect {
    https_redirect = true
    strip_query    = false
  }
}

# http proxy
resource "google_compute_target_http_proxy" "default" {
  name    = format("%s-http-lb-proxy", var.name)
  url_map = google_compute_url_map.default_http.id
  project = var.project_id
}

# forwarding rule
resource "google_compute_global_forwarding_rule" "default_http" {
  name                  = format("%s-lb-forwarding-rule", var.name)
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "80"
  target                = google_compute_target_http_proxy.default.id
  ip_address            = google_compute_global_address.default.id
  project               = var.project_id
}

# DNS record
resource "google_dns_record_set" "default" {
  project      = var.dns_zone_project_id != null ? var.dns_zone_project_id : var.project_id
  managed_zone = var.managed_zone
  name         = format("%s.", var.dns_name)
  type         = "A"
  ttl          = "60"

  rrdatas = [google_compute_global_address.default.address]

  depends_on = [
    google_compute_global_address.default
  ]
}

## Enable the certificate manager API #
resource "google_project_service" "certificate_manager" {
  service            = "certificatemanager.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

## Enable the Cloud DNS API ##
resource "google_project_service" "cloud_dns" {

  service            = "dns.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

# HTTPS certificate for the CDN
resource "google_compute_managed_ssl_certificate" "default" {
  provider = google-beta
  project  = var.project_id
  name     = "${var.name}-cert"

  lifecycle {
    create_before_destroy = true
  }

  managed {
    domains = [format("%s.", var.dns_name)]
  }
}

# SSL Policies
resource "google_compute_ssl_policy" "tls12_modern" {
  project         = var.project_id
  name            = "${var.name}-static-ssl-policy"
  profile         = "COMPATIBLE"
  min_tls_version = "TLS_1_2"
}

# HTTPS proxy
resource "google_compute_target_https_proxy" "default" {
  name             = format("%s-https-proxy", var.name)
  url_map          = google_compute_url_map.default.id
  ssl_certificates = [google_compute_managed_ssl_certificate.default.id]
  ssl_policy       = google_compute_ssl_policy.tls12_modern.id
  project          = var.project_id
}


# forwarding rule
resource "google_compute_global_forwarding_rule" "default_https" {
  name                  = format("%s-lb-forwarding-rule-https", var.name)
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL"
  port_range            = "443"
  target                = google_compute_target_https_proxy.default.id
  ip_address            = google_compute_global_address.default.id
  project               = var.project_id
}
