# sales-ops-agent: エージェント実行環境と CI デプロイ用の IAM。

resource "aws_iam_role" "runtime" {
  name = "sales-ops-agent-runtime"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "runtime" {
  name = "sales-ops-agent-runtime"
  role = aws_iam_role.runtime.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::sales-ops-agent-knowledge/*"] },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["arn:aws:logs:us-east-1:107085628208:log-group:/aws/lambda/sales-ops-agent:*"] }
    ]
  })
}

resource "aws_lambda_function" "runtime" {
  function_name = "sales-ops-agent"
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
