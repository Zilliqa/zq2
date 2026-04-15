################################################################################
# ZQ2 GCP Terraform logging exclusion filters
################################################################################

resource "google_logging_project_exclusion" "exclude_health_checks" {
  name        = "${var.chain_name}-exclude-health-check-syslog"
  project     = var.project_id
  description = "Exclude successful LB health check entries from syslog"
  filter      = "logName = \"projects/${var.project_id}/logs/syslog\" AND jsonPayload.message =~ \"GET /health HTTP/1.1\\\" 200\""
}

resource "google_logging_project_exclusion" "exclude_unmapped_severity" {
  name        = "${var.chain_name}-exclude-unmapped-severity-zilliqa"
  project     = var.project_id
  description = "Exclude zilliqa log entries with no severity (ANSI zilstats output)"
  filter      = "logName = \"projects/${var.project_id}/logs/zilliqa\" AND severity = DEFAULT"
}
