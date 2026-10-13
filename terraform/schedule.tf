resource "aws_cloudwatch_event_rule" "scan" {
  name                = "sentinel-scheduled-scan"
  description         = "Triggers the Sentinel auditor on a schedule"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "scan" {
  rule = aws_cloudwatch_event_rule.scan.name
  arn  = aws_lambda_function.sentinel.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sentinel.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scan.arn
}
