data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sentinel" {
  name               = "sentinel-auditor-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Lets the function write its own logs to CloudWatch
resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.sentinel.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Read-only permissions for the checks. No write or delete actions.
data "aws_iam_policy_document" "audit_read" {
  statement {
    sid = "ReadOnlyAudit"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVolumes",
      "iam:ListUsers",
      "iam:ListAccessKeys",
      "iam:ListMFADevices",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "audit_read" {
  name   = "sentinel-audit-read"
  role   = aws_iam_role.sentinel.id
  policy = data.aws_iam_policy_document.audit_read.json
}
