# incident-bot: エージェント実行環境と CI デプロイ用の IAM。

resource "aws_iam_role" "runtime" {
  name = "incident-bot-runtime"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "runtime" {
  name = "incident-bot-runtime"
  role = aws_iam_role.runtime.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::incident-bot-knowledge/*"] },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["arn:aws:logs:us-east-1:792120611933:log-group:/aws/lambda/incident-bot:*"] }
    ]
  })
}

resource "aws_lambda_function" "runtime" {
  function_name = "incident-bot"
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
