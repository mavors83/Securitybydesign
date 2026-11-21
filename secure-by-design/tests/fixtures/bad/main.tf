# Fixture con pattern volutamente insicuri: NON usare come esempio.
resource "aws_s3_bucket_acl" "a" {
  # sbd-expect-next: P-IAC-01
  acl = "public-read"
}
resource "aws_db_instance" "db" {
  # sbd-expect-next: P-IAC-02
  publicly_accessible = true
  # sbd-expect-next: P-IAC-03
  storage_encrypted   = false
}
resource "aws_kms_key" "k" {
  # sbd-expect-next: P-IAC-04
  enable_key_rotation = false
}
data "aws_iam_policy_document" "p" {
  statement {
    # sbd-expect-next: P-IAC-05
    actions   = ["*"]
    # sbd-expect-next: P-IAC-06
    resources = ["*"]
  }
}
resource "aws_security_group_rule" "ssh" {
  from_port   = 22
  # sbd-expect-next: P-IAC-08
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_launch_template" "lt" {
  metadata_options {
    # sbd-expect-next: P-IAC-09
    http_tokens = "optional"
  }
}
resource "azurerm_storage_account" "sa" {
  # sbd-expect-next: P-IAC-10
  min_tls_version = "TLS1_0"
}
resource "aws_cloudtrail" "t" {
  # sbd-expect-next: P-IAC-11
  enable_logging = false
}
