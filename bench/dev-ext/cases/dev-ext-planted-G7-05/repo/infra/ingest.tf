# qa-pilot: エージェント実行環境と CI デプロイ用の IAM。

resource "aws_iam_role" "ingest" {
  name = "qa-pilot-ingest"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}

resource "aws_lambda_function" "ingest" {
  function_name = "qa-pilot-ingest"
  role          = aws_iam_role.ingest.arn
  runtime       = "python3.12"
  handler       = "ingest.handler"
}
