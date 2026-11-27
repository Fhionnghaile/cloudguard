data "archive_file" "scanner" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/scanner.zip"
}

resource "aws_cloudwatch_log_group" "scanner" {
  #checkov:skip=CKV_AWS_158:CloudWatch encrypts log data at rest by default; a dedicated KMS CMK is out of scope for this cost-free showcase.
  name              = "/aws/lambda/cloudguard-scanner"
  retention_in_days = 365
}

resource "aws_lambda_function" "scanner" {
  #checkov:skip=CKV_AWS_117:Scanner calls only public AWS control-plane APIs; there are no private VPC resources for it to reach.
  #checkov:skip=CKV_AWS_116:Scheduled scanner; invocation failures surface via CloudWatch and EventBridge retries. A DLQ (SQS/SNS) is out of scope for this showcase.
  #checkov:skip=CKV_AWS_173:The only env var is the DynamoDB table name (not a secret); AWS-managed encryption at rest applies. A CMK is out of scope for this showcase.
  #checkov:skip=CKV_AWS_272:Code-signing config is out of scope for this single-maintainer showcase.
  function_name                  = "cloudguard-scanner"
  reserved_concurrent_executions = 2
  role                           = aws_iam_role.scanner.arn
  handler                        = "cloudguard.scanner.handler"
  runtime                        = "python3.12"
  timeout                        = 300
  memory_size                    = 256
  filename                       = data.archive_file.scanner.output_path
  source_code_hash               = data.archive_file.scanner.output_base64sha256

  environment {
    variables = { TABLE = aws_dynamodb_table.findings.name }
  }
  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.scanner]
}
