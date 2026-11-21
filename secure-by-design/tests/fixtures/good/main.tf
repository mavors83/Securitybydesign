resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_kms_key" "data" {
  enable_key_rotation     = true
  deletion_window_in_days = 30
}
resource "aws_db_instance" "payments" {
  storage_encrypted           = true
  publicly_accessible         = false
  manage_master_user_password = true
}
data "aws_iam_policy_document" "reader" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.reports.arn}/reports/*"]
  }
}
resource "aws_launch_template" "app" {
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
resource "azurerm_storage_account" "sa" {
  min_tls_version = "TLS1_2"
}
