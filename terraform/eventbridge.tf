resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "cloudguard-scan"
  schedule_expression = var.scan_rate
}
resource "aws_cloudwatch_event_target" "scanner" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.scanner.arn
}
resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
