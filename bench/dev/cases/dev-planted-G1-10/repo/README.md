# sales-ops-agent

sales-ops-agent は stark-labs の platform チームが保守する社内 AI エージェントです。ツール接続には MCP サーバを使い、評価スイートは GitHub Actions で実行します。

## セットアップ

1. `.env.example` を `.env` にコピーして値を設定します。
2. `make dev` でエージェントを起動します。

## セキュリティ

認証情報は環境変数から参照します。設定ファイルにトークンを貼り付けないでください。
