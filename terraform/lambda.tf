data "archive_file" "scanner" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/scanner.zip"
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws/lambda/cloudguard-scanner"
  retention_in_days = 30
}

resource "aws_lambda_function" "scanner" {
  function_name    = "cloudguard-scanner"
  role             = aws_iam_role.scanner.arn
  handler          = "cloudguard.scanner.handler"
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 256
  filename         = data.archive_file.scanner.output_path
  source_code_hash = data.archive_file.scanner.output_base64sha256

  environment {
    variables = { TABLE = aws_dynamodb_table.findings.name }
  }
  tracing_config { mode = "Active" }
  depends_on = [aws_cloudwatch_log_group.scanner]
}
