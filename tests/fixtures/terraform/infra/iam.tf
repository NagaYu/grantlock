# GitHub Actions deploys through OIDC
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "deploy_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name               = "gha-deploy"
  assume_role_policy = data.aws_iam_policy_document.deploy_trust.json
}

data "aws_iam_policy_document" "deploy" {
  statement {
    effect    = "Allow"
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = ["arn:aws:ecs:us-east-1:111122223333:service/agents/*"]
  }
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "deploy" {
  name   = "gha-deploy"
  policy = data.aws_iam_policy_document.deploy.json
}

resource "aws_iam_role_policy_attachment" "deploy" {
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy.arn
}

/* agent runtime role used by two compute resources */
resource "aws_iam_role" "agent" {
  name = "agent-runtime"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "agent" {
  name = "agent-inline"
  role = aws_iam_role.agent.id
  policy = <<EOT
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"},
    {"Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "arn:aws:logs:*:*:log-group:/agent/*"}
  ]
}
EOT
}

resource "aws_iam_role_policy_attachment" "agent_admin" {
  role       = aws_iam_role.agent.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # temporary!
}

resource "aws_lambda_function" "agent" {
  function_name = "agent"
  role          = aws_iam_role.agent.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  environment {
    variables = {
      LOG_LEVEL = "info"
    }
  }
}

resource "aws_ecs_task_definition" "agent" {
  family        = "agent"
  task_role_arn = aws_iam_role.agent.arn
  container_definitions = jsonencode([{ name = "agent", image = "ghcr.io/acme/agent:2.1.0" }])
}

resource "aws_iam_user" "ci" {
  name = "legacy-ci"
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}
