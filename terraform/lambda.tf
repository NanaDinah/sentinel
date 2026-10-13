data "archive_file" "sentinel" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/sentinel.zip"
  excludes    = ["**/__pycache__/**"]
}

resource "aws_lambda_function" "sentinel" {
  function_name    = "sentinel-auditor"
  role             = aws_iam_role.sentinel.arn
  runtime          = "python3.12"
  handler          = "sentinel.handler.lambda_handler"
  filename         = data.archive_file.sentinel.output_path
  source_code_hash = data.archive_file.sentinel.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }
}
