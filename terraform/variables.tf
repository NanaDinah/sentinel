variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "alert_email" {
  type        = string
  description = "Email address that receives Sentinel alerts"
}

variable "scan_schedule" {
  type        = string
  description = "How often Sentinel scans"
  default     = "rate(1 day)"
}
