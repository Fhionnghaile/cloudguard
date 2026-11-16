# Scanner role: read-only account audit (AWS-managed SecurityAudit) + write ONLY to the findings table.
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name               = "cloudguard-scanner"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# Broad READ for enumeration, scoped by AWS's managed read-only audit policy.
resource "aws_iam_role_policy_attachment" "audit" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Least-privilege WRITE: only this one table, only the actions the store uses.
data "aws_iam_policy_document" "scanner_write" {
  statement {
    sid       = "FindingsTableWrite"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.findings.arn, "${aws_dynamodb_table.findings.arn}/index/*"]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.scanner.arn}:*"]
  }
}
resource "aws_iam_role_policy" "scanner_write" {
  name   = "cloudguard-scanner-write"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner_write.json
}
