# GrantLock SPEC (Phase 1)

本書は Phase 1 で実装する仕様の正本である。タスク指示で「固定」とされた意味論はここに転記し、
実装上の解釈（指示に書かれていない細部）は DECISIONS.md に番号付きで記録する。

## 0. 絶対条件

- 秘密値を一切記録しない。inventory / lockfile / findings / SARIF / ログ / ベンチ期待値 / 報告書に
  値そのもの、および値の生ハッシュを書かない。記録してよいのは変数名・provider・storage class・
  形式分類（既知プレフィックス表に基づくクラス名とその表上のプレフィックス）のみ。
- スキャンコア（`grantlock/` のうち `cli.py` 以外）はネットワーク呼び出しをしない。
  対象リポジトリのファイルを読み JSON(dict) を返す純関数。
- 状態は `grantlock.json` のみ。`check` はロックファイルを絶対に書き換えない。

## 1. コア API（SaaS-ready seam）

```
grantlock.scan(repo_path)                  -> inventory   (schema: grantlock.inventory 1.0)
grantlock.lock(inventory)                  -> lockfile    (schema: grantlock.lock 1.0)
grantlock.diff(inventory, lockfile, policy)-> findings    (schema: grantlock.findings 1.0)
```

すべての JSON 文書は `schema_version` と `document` を持つ。CLI (`grantlock/cli.py`) は
これらを呼んでファイル入出力するだけの薄いラッパー。

## 2. 身分モデル（inventory の 1 エントリ = 1 binding）

| フィールド | 内容 |
|---|---|
| `identity_id` | `provider + ":" + credential.name` の決定的生成（特殊形は §2.1） |
| `component` | `{id, kind, name, file}`。kind ∈ `mcp_server` / `gha_workflow` / `env_decl` |
| `credential` | `{provider, type, name, storage, format}`。type ∈ api_key/oauth/service_account/token/password/unknown、storage ∈ vault_ref/env/inline/federated、format は storage=inline のときだけ形式分類 |
| `scopes` | 正規化済み権限リスト（§4）。不明なら `[]` |
| `scopes_known` | bool |
| `scope_source` | `explicit` / `implicit_default` / `read-all` / `write-all` / `declared` / `unknown` |
| `resources` | `[{kind, value}]`。kind ∈ host/package/image/environment/branch/trigger/role |
| `owner` | `{source, owners[], rule, line}` または `null` |
| `lifespan` | ephemeral / rotating / long_lived / unknown |
| `context` | `{federation_available: bool, reason}`（G6 の材料） |
| `evidence` | `[{file, line, locator}]`。locator はキーパス（値は含まない） |

1 つの identity を複数 component が使う場合、同じ `identity_id` のエントリが component ごとに並ぶ
（DECISIONS D-003）。

### 2.1 identity_id の特殊形

- GitHub Actions の暗黙トークン: `github:GITHUB_TOKEN@<workflow file>#<job id>`（ジョブごとに発行されるため）
- 連合（OIDC）: `<provider>:oidc:<subject>`。subject は role ARN / service account / client-id、
  またはそれが secrets 参照なら `secrets.<NAME>`
- 名前を持たないリテラル資格情報（ヘッダや action 入力）: `<provider>:<component id>:<locator>`
- MCP のリモート OAuth（静的資格情報なし）: `<provider>:oauth:<host>`

## 3. 対象面と読み取り規則

### 3.1 MCP 設定
- 対象: リポジトリ内の `*.json` で、トップレベルに `mcpServers`(dict) を持つもの、
  またはファイル名に `mcp` を含みトップレベルに `servers`(dict) を持つもの。
- サーバごとに `command`/`args`/`url`/`env`/`headers`/`oauth` を読む。
- env 値: 空・`${VAR}`・`${env:VAR}`・`$VAR`・`${input:x}`・プレースホルダ → storage=env（参照のみ）。
  非空リテラル → storage=inline、形式分類のみ記録し値は破棄。
- `headers.Authorization` 等も同様。`Bearer ${X}` は X への参照。
- 接続文字列にパスワードが埋め込まれていれば inline（ホスト名のみ resources に記録）。
- スコープ源: `oauth.scopes`、`*_SCOPES`/`*_SCOPE`/`*_ROLE`/`*_TOOLSETS` env、`--scopes`/`--scope`/`--role`/`--toolsets` 引数。

### 3.2 GitHub Actions
- `.github/workflows/*.yml|*.yaml`。component = `<workflow name>/<job id>`。
- 実効 permissions = ジョブの `permissions:` があればそれ、なければワークフローの `permissions:`、
  どちらもなければ `implicit_default`（scopes=[]、scopes_known=false）。
- `secrets.*` 参照（`${{ secrets.X }}` / `secrets['X']`）。ワークフロー env の参照は全ジョブに帰属。
- 連合: 実効 permissions に `id-token: write` があり、aws-actions/configure-aws-credentials
  (role-to-assume、静的キー入力なし) / google-github-actions/auth (workload_identity_provider) /
  azure/login (client-id かつ creds なし) / pypa/gh-action-pypi-publish (password なし) を使う
  → storage=federated、lifespan=ephemeral。連合 action の識別子入力に使われた secrets は資格情報として数えない。
- 静的クラウドキー（AWS_ACCESS_KEY_ID、credentials_json、azure creds、PyPI/npm token）→ G6 の材料。
- env / with / credentials の資格情報名キーにリテラル値 → inline。

### 3.3 .env / .env.*
- 変数名のみ読む。値は読まない（パーサは `=` 以降を捨てる）。資格情報らしい名前だけをエントリ化。
- component kind = `env_decl`（宣言面）。宣言は「消費」ではないため G5/G8 の計数から除く。

## 4. 権限の正規化
- GHA スコープ集合: actions, checks, contents, deployments, discussions, id-token, issues, packages,
  pages, pull-requests, repository-projects, security-events, statuses。レベル none < read < write。
  表現は `<scope>:<level>`（none は省略）。比較時は write ⊇ read に展開する。
- `read-all` / `write-all` は全スコープへ展開し、scope_source に元の形を残す。
- ワイルドカード / 管理者級: `write-all`、`*` を含むスコープ、管理者級トークン
  （admin, administrator, administratoraccess, administration, owner, root, superuser,
  および `admin` で終わるセグメント例: accountadmin, sysadmin）→ G3 の材料。

## 5. diff 分類（G1–G8）

| class | 条件 |
|---|---|
| G1 | storage=inline のエントリ |
| G2 | lock と同じ (identity, component) で正規化スコープが増えた、または explicit → implicit_default / write-all へ変わった |
| G3 | ワイルドカード / 管理者級グラント |
| G4 | owner=null |
| G5 | 同一 identity を 2 つ以上の消費 component（env_decl 以外）が共有 |
| G6 | 連合/短期化が可能な文脈（context.federation_available）での long_lived 静的キー |
| G7 | lock に無い identity_id |
| G8 | lock では消費 component から参照されていた identity が、現在どの消費 component からも参照されない |

各 finding は `change` を持つ: `introduced`（lock に無い/変化した状態）、`unchanged`（lock 済みの状態）、`removed`（G8）。

### 5.1 重大度
- デフォルト: 本番スコープの G2 / G3 / G7（change=introduced）= critical → check exit 1。その他 = warning（exit 0）。
- `change=unchanged`（lock 済み = 人間がレビュー済み）の状態 finding は warning を上限とする（DECISIONS D-010）。
- 本番判定: environment 名・ホスト名・role 名・component 名に `prod|production|prd|live` トークン、
  `.env.production` 等。判定根拠を findings に残す。`grantlock.policy.json` で上書き可能。

## 6. GrantBench
- dev = planted 80（G1–G8 各 10）+ clean 24 + diff_pair 16 = 120 件。seed 固定・決定的。
- 各 planted/clean ケースは `repo/`（`grantlock.json` を含むスナップショット）と `case.json`。
  diff_pair は `before/` と `after/`（after の `grantlock.json` は before から生成されたもの）。
- holdout: `--split holdout` は出力先がリポジトリ外かつ `GRANTLOCK_ALLOW_HOLDOUT=1` のときのみ。

## 7. 採点
- planted: ケースの対象クラスの planted 項目すべてについて (class, file, component.name) が一致する finding があれば
  そのケースを検出とする（ケース単位・厳格）。クラス別 recall。項目単位 recall も併記。
- clean: G クラスの finding が 1 件でもあれば誤検出ケース。誤検出率 = 誤検出ケース / clean 件数。
- diff_pair: 予測クラス集合（重複除去・ソート）が期待ラベルと完全一致で正解。
- ベースライン: ファイル単位で planted と突き合わせ、G1 のみ判定可能。その他は構造上 recall 0。
