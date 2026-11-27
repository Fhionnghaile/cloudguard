variable "region" {
  type    = string
  default = "us-east-1"
}

variable "table_name" {
  type    = string
  default = "cloudguard"
}

variable "scan_rate" {
  type    = string
  default = "rate(1 hour)"
}

variable "tags" {
  type    = map(string)
  default = { app = "cloudguard", managed_by = "terraform" }
}
