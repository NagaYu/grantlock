# research-scout: IAM for the agent runtime and CI deploys.

resource "aws_iam_role" "runtime" {
  name = "research-scout-runtime"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "runtime" {
  name = "research-scout-runtime"
  role = aws_iam_role.runtime.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::research-scout-knowledge/*"] },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["arn:aws:logs:us-east-1:623225834455:log-group:/aws/lambda/research-scout:*"] }
    ]
  })
}

resource "aws_lambda_function" "runtime" {
  function_name = "research-scout"
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
