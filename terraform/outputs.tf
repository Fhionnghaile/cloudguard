output "table_name" { value = aws_dynamodb_table.findings.name }
output "scanner_arn" { value = aws_lambda_function.scanner.arn }
output "scanner_role" { value = aws_iam_role.scanner.arn }
