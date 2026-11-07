# repo-gardener: エージェント実行環境と CI デプロイ用の IAM。

resource "aws_iam_user" "ci" {
  name = "ci-deployer"
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}
