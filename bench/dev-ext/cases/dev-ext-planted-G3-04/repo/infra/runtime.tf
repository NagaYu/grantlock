# triage-agent: IAM for the agent runtime and CI deploys.

resource "aws_iam_role" "runtime" {
  name = "triage-agent-runtime"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "runtime" {
  name = "triage-agent-runtime"
  role = aws_iam_role.runtime.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["*"], Resource = ["*"] }, { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::triage-agent-knowledge/*"] },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["arn:aws:logs:us-east-1:321560803633:log-group:/aws/lambda/triage-agent:*"] }
    ]
  })
}

resource "aws_lambda_function" "runtime" {
  function_name = "triage-agent"
  role          = aws_iam_role.runtime.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "build/lambda.zip"
  environment {
    variables = {
      LOG_LEVEL = "info"
    }
  }
}
