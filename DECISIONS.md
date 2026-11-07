# DECISIONS

仕様に書かれていない細部・仕様との衝突をここに記録する。衝突時は仕様側の解釈を優先する。

## D-001 YAML 読み込みに PyYAML を使う
GitHub Actions ワークフローは YAML 1.1 の実用サブセット（アンカー、複数行文字列、フロー記法）を
多用し、自前パーサは誤読リスクが高い。PyYAML の `safe_load` のみを使い（任意オブジェクト構築なし）、
YAML 1.1 で `on:` が真偽値 `True` に化ける既知の挙動はパーサ側で `"on"` に戻す。

## D-002 JSON スキーマ検証に jsonschema を使う
inventory / lockfile / findings / ベンチケースの検証に Draft 2020-12 の jsonschema を使う。
スキーマは `additionalProperties: false` を多用し、値が自由文字列として紛れ込む余地を減らす
（秘密値混入の構造的防止）。スキーマ自体はコード内データとして持ち、ネットワーク解決はしない。

## D-003 inventory のエントリは (identity, component) の binding 単位
仕様は「inventory の1エントリ」に単数の `component` を持たせ、かつ `identity_id` を provider+名前から
決定的に作る。同じ資格情報を複数 component が使えば同じ `identity_id` が複数エントリに現れる。
G5（共有）は同一 `identity_id` の消費 component 数で判定する。G2 は同じ (identity, component) の比較。

## D-004 inventory への追加フィールド
固定フィールドに加え、`scope_source`（暗黙のデフォルトを区別するため）、`context`（G6 の材料）、
`evidence`（ファイル・行・キーパス。値は含まない）、`credential.format`（inline のときのみ形式分類）を持つ。
固定フィールドの意味は変えていない。

## D-005 秘密の形式分類は閉じた列挙 + 表上のプレフィックスのみ
`credential.format = {class, prefix}`。class は schemas.FORMAT_CLASSES の列挙、prefix は
model.FORMAT_TABLE に書かれた固定文字列（例 `sk-`, `ghp_`, `AKIA`）で、検査した値からは切り出さない。
長さ・エントロピー・ハッシュは記録しない（オフライン推測の材料になるため）。

## D-006 資格情報名の判定は名前規則、リテラルは形状規則
名前: 末尾トークンが TOKEN/SECRET/PASSWORD/PAT/CREDENTIALS/DSN 等、または KEY の直前が
API/ACCESS/SECRET/PRIVATE/… もしくは既知 provider 名（`PUBLIC_KEY`, `PUBLISHABLE_KEY`, `CACHE_KEY` 等は除外）、
または DB 接続 URL 名・WEBHOOK・資格情報ファイルパス名。`*_SCOPES`/`*_ROLE`/`*_TOOLSETS` は
スコープ宣言として扱い資格情報ではない。
リテラル: 既知形状（表）に一致すれば名前に関係なく inline。資格情報名のキーに非プレースホルダ・
非設定値（真偽値・数値・パス・パスワードなし URL を除く）のリテラルがあれば inline（`generic_literal`）。

## D-007 AWS 静的キーの 2 片は 1 identity
`AWS_SECRET_ACCESS_KEY` は `AWS_ACCESS_KEY_ID` の別名として同じ identity_id に正規化する（同一キーペア）。

## D-008 MCP 設定の細部
- `.vscode/mcp.json` は JSONC（コメント・末尾カンマ）なので、厳密 JSON で失敗した場合のみコメント除去して再読込する。
- `${input:x}`（VS Code のプロンプト入力）は参照扱い（storage=env）。値はリポジトリに存在しない。
- env のキーが資格情報名で値が単一参照 `${OTHER}` のとき、identity 名は参照元変数 OTHER（.env.example と突き合うため）。
- 名前を持たないリテラル（ヘッダ・引数・URL クエリ・oauth ブロック）は `<provider>:<component id>:<locator>` を identity_id にする。
  同名ヘッダを持つ別サーバ同士が誤って「共有」（G5）にならないようにするため。
- 静的資格情報を持たないリモート（url）サーバは委任 OAuth の identity（type=oauth, storage=vault_ref,
  lifespan=rotating）として記録する。クライアントがトークンを保管するため vault_ref とした。
- スコープ源: `oauth.scopes`、`*_SCOPES`/`*_SCOPE`/`*_ROLE`/`*_TOOLSETS` env、`--scopes`/`--scope`/`--role`/`--toolsets`/`--permissions` 引数。
  toolset は `toolset:<x>`（`all` は `toolset:*`）、role は `role:<x>` に正規化。サーバのスコープはそのサーバの全資格情報エントリに付与する。
- MCP の静的クラウドキー（aws/gcp/azure）は「短期化が可能な文脈」（SSO プロファイル、ADC、az login）として G6 の材料にする。

## D-009 GitHub Actions の細部
- 暗黙の `GITHUB_TOKEN` はジョブごとに発行されるため、identity_id を `github:GITHUB_TOKEN@<file>#<job>` とし、
  そのジョブの実効 permissions をスコープとする（storage=vault_ref、lifespan=ephemeral）。
  `secrets.GITHUB_TOKEN` / `github.token` の参照は新しい identity を作らずこのエントリに帰属させる。
  これを provider+名前だけで作ると、ワークフローが 2 本あるだけで全リポジトリが G5 になるため。
- job の `permissions:` はワークフロー側を（マージせず）置き換える（GitHub の仕様どおり）。
  どちらも無いときは `implicit_default`（scopes=[]、scopes_known=false）。リポジトリ/組織設定に依存し
  リポジトリから決められないため値を推測しない。
- `secrets.*` はすべて資格情報として扱う（secrets ストアに置かれている時点で秘匿対象）。名前から type が
  決まらないものは type=unknown / lifespan=unknown。storage=vault_ref。
- 連合 action の識別子入力（role-to-assume、workload_identity_provider、service_account、client-id、
  tenant-id 等）に使われた secrets は資格情報として数えない（principal の名前であって鍵ではない）。
- `id-token: write` が無いのに OIDC 構成の action を使っている場合も federated として記録し、警告を残す。
- G6 の「連合が可能な文脈」は provider 単位のプラットフォーム可用性で判定する: GitHub Actions は
  AWS / GCP / Azure / PyPI / npm への OIDC を常に提供するため、これらの静的キーを GHA で参照すれば G6 の材料。
  同一ワークフロー内に既に OIDC があるかどうかは要件にしない（例示は十分条件の一例と解釈）。
- インライン検出: env / with / credentials のキーに対するリテラル、および `run:` スクリプト中の既知形状トークン。
  ワークフロー env は全ジョブに帰属するが、再利用ワークフロー呼び出しジョブ（`jobs.<id>.uses`）には伝播しない。
- `secrets: inherit` は全 secrets を渡すが Phase 1 では列挙できないため inventory の warnings に記録する。

## D-011 .env の値は読まない（G1 の対象外）
仕様どおり `.env` / `.env.*` からは変数名だけを取り出す。宣言正規表現は名前グループしか捕捉しない。
唯一の例外として、`=` の直後が閉じていない引用符で始まる場合に限り、引用符が閉じる行まで読み飛ばす
（PEM 鍵などの継続行を「宣言」と誤読し、鍵の断片を変数名として記録してしまう事故を防ぐため）。
値の内容は分類も保持もしない。結果として、コミットされた `.env` に実値が入っていても GrantLock は
G1 として検出しない（storage=env として記録）。これは仕様の帰結であり、Phase 2 で再検討する。
`.env.<suffix>` の suffix が example/sample/template/local 等でなければ environment リソースとして記録する。

## D-012 owner 解決
- CODEOWNERS は GitHub の探索順（`.github/CODEOWNERS` → `CODEOWNERS` → `docs/CODEOWNERS`）で最初の 1 つ。
  パターンは gitignore 風、最後に一致した規則が勝つ。所有者なしの規則に一致した場合は owner=null（明示的な無所有）。
  `docs/*` は直下のみ（GitHub の文書どおり）。
- 「宣言された所有者」は `grantlock.policy.json` の `declared_owners`（component id → owners）で表し、CODEOWNERS より優先する。
  MCP 設定や workflow に独自キーを足すとクライアント側で拒否されうるため、別ファイルにした。
- owner は component が定義されたファイルで決まる（エントリ = binding 単位）。
- スキャンはシンボリックリンクを辿らない（リポジトリ外の読み取り防止）。`node_modules` 等は除外。

## D-010 状態クラスの change と重大度上限
check は「変更」を分類するが、G1/G3/G4/G5/G6 は状態でもある。各 finding に `change` を持たせる:
`introduced`（lock に無い・lock から状態が変わった）/`unchanged`（lock 済みの状態）/`removed`（G8）。
本番 G3 が既に `grantlock.json` に記録済み（= 人間が `grantlock lock` でレビュー・コミット済み）の場合は
critical ではなく warning を上限とする。仕様の「権限の変更を正とするには人間が lock を実行して差分を
コミットする（これがレビュー面）」に従い、レビュー済みの状態で CI を永久に落とさないため。
新たに導入された本番 G2/G3/G7 は既定どおり critical（exit 1）。状態 finding 自体は毎回報告する。

## D-013 diff の細部
- G2: 同じ (identity, component) で `expand(new) - expand(old)` が空でない（write ⊇ read）。
  さらに「既知だったスコープが未知になった」（explicit → implicit_default、toolsets 指定の削除など）も
  上限が外れた拡大として G2（`scope_source_change`）。スコープの縮小・新たに既知になったものは drift。
- G5: env_decl（宣言）を除いた消費 component が 2 つ以上。ジョブ単位で component なので、同じ secret を
  同一ワークフローの 2 ジョブで使うと G5（仕様の component 定義に従う）。
- G7: identity_id が lock に無ければ binding ごとに 1 件。既存 identity の新しい binding は G7 ではなく
  drift `binding_added`（共有になれば G5 が出る）。
- G8: lock で消費 component から参照されていた identity が、現在どの消費 component からも参照されない
  （.env.example に宣言が残っていても休眠）。lock の消費 binding ごとに 1 件、行番号は null。
- 分類に当たらない差分（binding 追加/削除、スコープ縮小、owner/resources/lifespan/storage 変化）は
  `drift` に記録し、`summary.lock_in_sync` で lock の再生成が必要かを示す。exit code には影響しない。
- 本番判定（Phase 1 ヒューリスティクス）: resources（trigger 以外: environment/host/role/branch/image/package）、
  component 名、資格情報名に `(^|非英数)(prod|production|prd|live)(非英数|$)`（大文字小文字無視）。
  一致した根拠文字列を `production.evidence` に残す。`production_patterns` で置換可能。
- 重大度 `off` の finding は出力しない。

## D-014 GrantBench の構成
- 各ケースの `grantlock.json` は「変更前（レビュー済み）」のスナップショットに対して GrantLock 自身の
  `lock` で生成する。実運用でも lock は GrantLock が作るため。期待ラベル（planted / expected_labels）は
  生成器が仕様（SPEC.md §5）から手で定めたもので、GrantLock の出力から作っていない。
- planted ケースは「ベース（クリーン）→ lock → 変異 1 つ」。変異が仕様上ほかのクラスも同時に生む場合
  （例: 静的キーへの置換は G6 と同時に新 identity の G7・旧 role の G8）は許容し、recall は planted に
  書いたクラスだけで測る。
- 各クラス 6〜8 種類の変異バリアントを循環させて 10 件を作る。言語は en/ja を交互（README、
  ワークフローのコメントと step 名、.env.example のコメント、CODEOWNERS コメント、JSONC コメント）。
- すべてのベースに「紛らわしいが正当な設定」（GITHUB_HOST の URL、プロキシ URL、TOKEN_CACHE_DIR、
  `permissions: {}`、`if:` 式、PUBLISHABLE_KEY、`${input:}` ヘッダ）から 3 つを無作為に入れ、clean の
  誤検出測定を現実的なノイズの上で行う。これらは採点前に決め、採点結果を見て変更していない。
- 秘密らしい文字列はすべて生成時に `FAKE` を含むダミー（`sk-FAKE…`, `ghp_FAKE…`, `AKIAFAKE…` 等）。
  値はメモリ上の Sink にだけ集め、case.json / manifest / grantlock.json には書かない（テストで確認）。
- 生成物 `bench/dev/` は seed から再現できるためコミットせず、`bench/dev.manifest.json`（ケース一覧と
  corpus_sha256）だけをコミットする。
- holdout: `check_holdout_allowed` は `GRANTLOCK_ALLOW_HOLDOUT` が厳密に `"1"` かつ出力先がこの
  リポジトリの外のときだけ通す。dev と別 seed。Phase 1 ではガードの単体テストのみで、生成はしない。
- diff_pair の正解判定は「予測クラス集合（重複除去・ソート）== expected_labels」の完全一致。

## D-015 採点の定義
- planted のクラス別 recall は**ケース単位・厳格**: そのケースの対象クラスの planted 項目すべてについて、
  (class, file, component.name) が一致する finding があれば検出。項目単位の recall も併記する。
- clean の誤検出: G クラスの finding（重大度を問わない）が 1 件でもあれば誤検出ケース。drift は数えない。
- diff_pair: `after/` を `after/grantlock.json`（= before の lock）で check し、予測クラス集合が
  expected_labels と完全一致で正解。
- ベースライン: PATH に無ければ実行せず `NOT RUN` と理由を記録（インストールはしない）。実行時は
  gitleaks `detect --no-git --redact`、trufflehog `filesystem --no-verification --no-update`（プロバイダへの
  検証通信をしない）。出力は (file, rule) だけ残し Secret/Match/Raw 等は解析時に捨てる。G1 はファイル一致で
  判定、他クラスは構造上見えないため 0 と記録。diff_pair は対象外（N/A）。

## D-016 開発中にテスト期待値を修正した記録（透明性のため）
- `test_mcp_parser.py::test_evidence_has_lines_and_locators_only`: 期待行を 9 → 8 に修正。フィクスチャ
  `clean.mcp.json` で `"GITHUB_PERSONAL_ACCESS_TOKEN"` の env キーは 8 行目にあり、期待値の数え間違いだった
  （意味論は「env キーの行を指す」で不変。実装側も args 中の同名文字列ではなく env キーを指すよう修正した）。
- それ以外の失敗（camelCase のキー名 `clientSecret` の判定、文脈からの provider 推定、ワークフロー env の
  inline 検出漏れ、再利用ワークフロー呼び出しジョブへの env 伝播、CODEOWNERS の `docs/*` 意味、
  本番判定に image/package リソースを含めるか）は実装側を修正した。dev コーパスの採点結果を見た後に
  検出器・生成器・期待ラベルを変更したことはない（初回採点で全項目一致）。

## D-017 CLI
`grantlock scan|lock|check`。check の exit code: 0 = critical なし、1 = critical あり、2 = 入力エラー
（lock 不在・lock/policy 不正）。`--format text|json|sarif`。SARIF の level は critical→error、warning→warning。
`lock` は内容が同一なら書き込まない。

## D-018 ベースラインの導入と実測（初版後の追記）
オーナー承認のうえ Homebrew 公式 tap から gitleaks 8.30.1 / trufflehog 3.99.8 を導入して実測した。
コーパス・期待ラベル・採点規則は変更していない（corpus_sha256 不変）。ダミー秘密の形式が実在形式に
忠実でないためベースラインの G1 が不利になっている可能性を報告書に明記した。採点後のコーパス変更は
後付け調整になるため行わず、Phase 2（holdout 作成時）に「実形式に忠実な偽ダミー」へ改める。

# Phase 2

## D-019 dev の凍結はアーカイブ方式、アーカイブはコミットする
`bench/dev/` を変更前に `bench/dev-frozen/` へコピーし、corpus_sha256（806d821b…）一致を確認した。
`bench/dev/` は .gitignore 対象だが、`bench/dev-frozen/` は**コミットする**（約 2.3 MB、1788 ファイル）。
「一切編集していない」ことを git 履歴とハッシュテストの両方で検証可能にするため。中のダミー秘密は
すべて `FAKE` を含む無効値（Phase 1 D-014）。回帰確認は再生成ではなく、このコピーの再採点で行う。

## D-020 `strict_recorded_g3`（デフォルト false）
D-010 はオーナー追認済みの正式意味論として維持する。ポリシーに `strict_recorded_g3: true` を書いたときだけ、
lock 記録済みの本番 G3 も critical のままにする。G3 以外・非本番には影響しない。

## D-021 G8 の指す先は Phase 1 のまま（.env 宣言には出さない）
holdout 作成プロンプトは G8 の `file` を「休眠になった身分が宣言されていたファイル」と書いており、.env.example を
記録される可能性がある。Phase 1 の G8 は「参照していた消費 component」に出す（D-013）。宣言側にも出すよう
変えると Phase 1 の未変更テスト（`test_G8_server_removed_but_still_declared`）が壊れ、GATE 2 基準 1 に反するため
変えない。holdout でこれによる不一致が出た場合は「慣行差」として分けて報告する（G8 は GATE 2 の判定対象外）。

## D-022 新面の component 種別と「宣言」種別（適用マトリクスの前提）
スキーマの COMPONENT_KINDS に追加（列挙値の追加のみで既存文書はそのまま有効なため schema_version は 1.0 のまま。
Phase 1 の未変更テストが 1.0 を固定していることも理由。Phase 3 で 1.1 化を検討）:
- 消費 component: `compose_service`、`k8s_workload`、`terraform_workload`（Lambda / ECS タスク / Cloud Run 等、
  ロールやサービスアカウントを**使う**計算資源）
- 宣言 component（G5 の共有数・G8 の「参照」から除外。env_decl と同じ扱い）: `k8s_service_account`、`k8s_secret`、
  `k8s_rbac`（Role/ClusterRole/Binding）、`terraform`（IAM ポリシー・ロール・キー等の定義資源）
プロンプトの「component 種別は terraform」「k8s_workload / k8s_service_account」に対し、Secret・RBAC・計算資源を
区別する種別を足した。component の name は指示どおり「変更が書かれたリソース」の metadata.name / アドレス。
`diff._consuming` は `schemas.DECLARATION_KINDS` を参照するよう一般化（Phase 1 の挙動は不変）。

## D-023 新面の適用マトリクス（holdout 作成前に確定・コミット）
| 面 | G1 | G2 | G3 | G4 | G5 | G6 | G7 | G8 |
|---|---|---|---|---|---|---|---|---|
| docker-compose | ✓ | – | – | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kubernetes | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Terraform | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
compose の G2/G3 を対象外とする理由: compose には資格情報に付く権限スコープのモデルが無い（`privileged` /
`cap_add` / docker.sock マウントはコンテナ実行権限であり、GrantLock の身分＝資格情報の権限ではない）。
holdout 採点で compose×G2/G3 のケースがあれば、プロンプトの規則どおり分母から除外し、その件数と、
除外しなかった場合の数値も併記する（後付けの除外に見えないよう、このマトリクスは holdout 生成前にコミットする）。

## D-024 docker-compose の細部
- 発見: ファイル名 `compose(.<x>).ya?ml` / `docker-compose(.<x>).ya?ml` で、トップレベル `services` が辞書。
  `<x>` が override/local/example 等以外なら environment リソース（例 `docker-compose.prod.yml` → prod）。
- `${VAR:-default}` の default がリテラル秘密なら inline（既定値に鍵を書く漏洩）。値部分にパスワード入り URL があれば inline。
- 資格情報名キーの値が単一の `${OTHER}` なら identity 名は OTHER、部分参照（`postgres://u:${PW}@h`）ならキー名
  （MCP の D-008 と同じ規則）。値なしの環境変数（`- SENTRY_DSN` / `GITHUB_TOKEN:`）はホスト環境からの参照。
- env_file は参照ファイル 1 つを 1 identity（`local:env_file:<正規化パス>`、type unknown）として扱う。中身は読まない。
  複数 service が同じ env_file を参照すると G5。
- secrets: service 側参照をトップレベル定義で解決。`environment:` 由来は storage=env、`file:`/`external` は vault_ref
  （ファイルの中身は読まないため、コミットされた secrets ファイルの値は G1 にしない）。type が名前から決まらなければ password。
- トップレベルで定義されたが一度も使われない secret はエントリを作らない。G8 は Phase 1 と同じく「lock では使われて
  いたが使われなくなった」遷移で出る（状態としての未使用定義は G8 にしない）。プロンプトの「トップレベル env_file」は
  compose 仕様に存在しないため対象外。
- compose の静的クラウドキーは「短期化が可能な文脈」（SSO プロファイル・インスタンスロールのマウント）として G6 の材料。

## D-025 テスト期待値の修正記録（Phase 2 Step 1）
`test_compose_parser.py::test_environment_map_and_list_forms` の期待 identity を `postgres:PG_PASSWORD` から
`postgres:DATABASE_URL` に変更した。期待値を書いた時点で D-008 の「部分参照ならキー名」規則と矛盾していたため、
既存の確定規則（D-008）側に合わせた。同ステップのもう 1 件の失敗（パスワード入り URL のホスト名が resources に
入らない）は実装を修正した。

## D-026 Kubernetes の細部
- 発見: `.yaml`/`.yml` のうち `apiVersion:` と `kind:` を含み、ドキュメントが apiVersion/kind/metadata.name を持つもの
  （ワークフロー・compose は除く）。`kind: List` の items も展開。Helm テンプレート等で YAML として壊れていれば
  警告を残してそのファイルを飛ばす（クラッシュしない）。
- 参照がファイルをまたぐため、パーサは「ファイル単位で object を集める」→「リポジトリ全体で解決する」の 2 段（どちらも純関数）。
- Secret: キー名・type だけ。`data` の値は base64 デコードせず、非空なら inline・形式 `k8s_secret_data_base64`。
  `stringData` は値を形状分類だけして破棄。空・プレースホルダは vault_ref（宣言のみ）。SealedSecret の encryptedData は vault_ref。
  `kubernetes.io/service-account-token` 型は SA の長期トークン（long_lived）で、bound token が使えるため G6 の材料。
- identity: Secret キー = `<provider>:k8s-secret:<ns>/<secret>.<key>`、SA = `kubernetes:serviceaccount:<ns>/<sa>`。
  SA の provider は annotation の有無で変えない（IRSA を足しただけで新規 ID＝G7 にならないように）。IRSA / GKE WI /
  Azure WI の annotation があれば storage=federated。
- RBAC: Binding の subjects（ServiceAccount、User/Group）に、参照 Role/ClusterRole の rules を
  `rbac:<cluster|ns>:<verb>:<resource[.group]>[#name]` として付与。component は**ルールが書かれた Role/ClusterRole**
  （リポジトリに無い組み込みロール参照なら Binding）。G3 材料: `*`、`cluster-admin` 等の管理者級、クラスタ全体の
  secrets get/list/watch、impersonate/escalate/bind。
- 消費者は workload のみ（D-022）。`serviceAccountName` を明示した場合だけ SA を使う binding を作る（暗黙の default SA
  は作らない。全 workload が default SA を共有して G5 だらけになるのを避ける）。env の secretKeyRef、envFrom.secretRef
  （リポジトリ内に Secret があれば全キーに展開）、secret ボリューム、imagePullSecrets を参照として読む。env のリテラルは
  他の面と同じ inline 判定。静的クラウドキーの Secret を参照する workload は G6 の材料（IRSA/WI が使えるため）。

## D-027 テスト修正記録（Phase 2 Step 2）
`test_k8s_parser.py` のヘルパ `_find` が同名の ServiceAccount と Deployment（どちらも `agent`）を区別できず失敗したため、
component 種別でも絞れるよう引数を足した（期待値は不変）。もう 1 件（envFrom が stringData のキーへ展開されない）は実装を修正。

## D-028 Terraform の細部
- HCL は対象リソース限定の構造リーダ（ブロック入れ子、`${}` 補間付き文字列、heredoc、リスト/オブジェクト/関数呼び出しの
  括弧対応、`#` `//` `/* */` コメント）。構造が読めないファイルは警告を残してスキップし、例外を投げない。
  式は評価しない（`var.*`・remote state・`count`/`for_each` は読まない）。
- 解決単位はディレクトリ（= モジュール）。identity_id は `<provider>:terraform:<dir>//<address>`（別ディレクトリの同名
  アドレスを同一 ID と誤認しないため）。component name はプロンプトどおりルートモジュール形式のアドレス。
- 宣言（kind `terraform`）: `aws_iam_role`（federated / ephemeral、信頼ポリシーに Federated / AssumeRoleWithWebIdentity
  があれば `trust:web-identity`）、`aws_iam_user`、`google_service_account`、`azurerm_user_assigned_identity`、
  ポリシー（`aws_iam_policy` + 各 attachment、`aws_iam_role_policy`/`aws_iam_user_policy`、ロールの `inline_policy`/
  `managed_policy_arns`）、`google_*_iam_member|binding`、`azurerm_role_assignment`、静的キー資源
  （`aws_iam_access_key`、`google_service_account_key`、`azuread_*_password` = long_lived、G6 の材料）。
- ポリシーのスコープは `iam:action:<a>` / `iam:resource:<r>`（Allow 文のみ。Deny は付与ではない）、管理ポリシーは
  `iam:managed:<name>`、GCP/Azure ロールは `role:<name>`。`data.aws_iam_policy_document` 経由ならエントリの component は
  **文が書かれた data ブロック**（変更が書かれたリソース）。G3: Action に `*` を含む、Resource がちょうど `*`
  （`arn:...:bucket/*` のような ARN 内の `*` はオブジェクト範囲であり除外）、AdministratorAccess、roles/owner、
  roles/editor、Owner、Contributor。
- 消費者（kind `terraform_workload`）: Lambda、ECS タスク定義、インスタンスプロファイル、EKS Pod Identity、CodeBuild、
  Step Functions、Cloud Run、Cloud Functions、GKE ノードプール、Azure Web/Function/Container App 等がブロック内で
  ロール/サービスアカウントを参照したもの。G5 は同じロールを 2 つ以上の計算資源が使う場合、G8 はロールが
  どの計算資源からも使われなくなった場合（D-013 と同じ遷移規則）。
- G6: 静的キー資源と provider ブロックのリテラル鍵は、AWS/GCP/Azure が連合を提供するため常に材料（D-009 と同じく
  プラットフォーム可用性で判定）。同じモジュールに `aws_iam_openid_connect_provider` 等があれば理由文に付記する。
- G1: すべてのブロック（resource / provider / variable の default / locals / module 入力 / data）の属性で、補間を含まない
  文字列リテラルが D-006 の規則で秘密と判定されたもの。provider の `access_key`/`secret_key` は 1 identity に統合。
  ポリシー属性（policy / assume_role_policy）は秘密判定の対象外。

## D-029 テスト修正記録（Phase 2 Step 3）
`test_terraform_parser.py::test_literals_classified_and_discarded` で `aws_db_instance.password` の provider を
`unknown` と期待していたが、実装は Phase 1 からの文脈推定規則（D-006・`infer_provider` の context）でリソース型
`aws_db_instance` から `aws` を推定した。既存の確定規則どおりの結果なので期待値を `aws` に修正した。

## D-030 scan の発見規則（Phase 2）
compose ファイル名に一致 → compose。それ以外の `.yaml`/`.yml`（ワークフロー以外）→ Kubernetes 候補（`apiVersion:` と `kind:`
を含むものだけ解析）。`.tf` → Terraform。K8s と Terraform はリポジトリ全体のオブジェクトを集めてから一括で解決する。
owner は Phase 1 と同じく component のファイルに対する CODEOWNERS / declared_owners で解決（新面も同一経路）。

## D-031 宣言 component の新規 binding による権限追加も G2
K8s / Terraform では権限の追加が「既存 identity に新しい付与リソース（RoleBinding、IAM member、ポリシー attachment 等）が
増える」形で起きる。D-013 では新規 binding を drift としていたが、それは MCP/GHA の「消費の開始」を想定した規則だった。
宣言種別（D-022）の component で scopes が既知かつ非空の新規 binding については、その identity が lock 全体で保持していた
スコープ集合（展開後）に対する差分が空でなければ G2 とする。既存スコープだけの新規 binding は G2 にしない。
env_decl はスコープを持たないため Phase 1 の挙動は不変（凍結 dev の再採点で確認する）。

## D-032 公開 API `grantlock.diff` の修正（Phase 1 の潜在バグ）
`grantlock/__init__.py` の関数 `diff` は、サブモジュール `grantlock.diff` が初めて import された時点でパッケージ属性を
モジュールで上書きされ、README 記載の `grantlock.diff(inventory, lock)` が呼べなくなっていた（Phase 1 のテストは
`from grantlock.diff import diff` で呼んでいたため未検出）。サブモジュールを先に読み込んでから関数を束縛するよう修正し、
`tests/test_public_api.py` を追加。Phase 1 のテストは無変更。

## D-033 dev-ext コーパス
- 別 split `dev-ext`（seed 20261121）。`bench/dev` / `bench/dev-frozen` とは独立。レイアウトは holdout と同じ lockfile なし形式
  （planted: base/ + repo/、clean: repo/、diff_pair: before/ + after/）にし、採点はメモリ上で lock を生成する
  `grantbench/lockless.py` を dev-ext と holdout で共用する（元コーパスへの書き込みなし。一時コピーも不要）。
- 規模: planted 48（各クラス 6、適用マトリクス D-023 に従い compose は G2/G3 なし、K8s/Terraform は G2/G3 各 3）、
  clean 12、diff_pair 8（良性 3）。クラウドは AWS/GCP を変異の要求に応じて切替。en/ja はおよそ 2:1。
- ダミー秘密は D-018 に従い実形式（Anthropic `sk-ant-api03-`+95 字、OpenAI `sk-proj-`+74+`T3BlbkFJ`+74、`ghp_`+36、
  `AKIA`+16 base32、AWS secret 40 字、Slack `xoxb-` 数字列 + 24 字）で、本体に `FAKE` を含む乱数値。
- clean の near-miss（`${VAR:-}`、`*_SECRET_FILE` パス、configMapKeyRef、条件付き Deny `*`、default なし sensitive 変数、
  resourceNames 限定の secrets get、ARN 内 `/*`）は採点前にコミットした。
- この生成器・変異・期待ラベルは**採点を実行する前に**コミットする（後付け調整の防止）。

## D-034 dev-ext の採点結果とベースラインの公平性（記録）
採点前コミット（Step 5a）の後に実行。GrantLock: 全クラス 6/6、clean 0/12、diff 8/8（同一作者バイアスあり）。
ベースライン（実形式ダミー）: gitleaks G1 5/6（取りこぼしは接続文字列内パスワードの 1 件のみ。Anthropic / OpenAI / Slack /
AWS の各ルールは一致）、trufflehog G1 6/6。dev（接頭辞のみの模倣ダミー）の 6/10・7/10 から改善しており、D-018 の
「ダミー形式がベースラインに不利だった」仮説を支持する。G2–G8 の 42 ケースでは両ツールとも finding 0 件。
`bench/dev-ext/` は再生成可能なためコミットせず、`bench/dev-ext.manifest.json` のみコミットする。

## D-035 証拠パック `grantlock evidence`
- 出力: `grantlock-evidence.json`（スキーマ `grantlock.evidence` 1.0、閉じたオブジェクト）と `grantlock-evidence.md`。
  内容: 免責文、入力スキーマ版・実効ポリシー（declared_owners は件数のみ）・lock 同期状態、インベントリ要約
  （component 種別/storage/lifespan 別件数、owner 有無）、findings（クラス・重大度・change・位置・本番判定根拠・理由・対応制御）、
  lock 差分履歴の要約、制御対応表。
- 差分履歴: コアは `git` を実行しない（ネットワーク不在テストが subprocess を禁止しているため）。利用者が
  `--previous-lock`（例: `git show HEAD~1:grantlock.json` の出力）を渡したときだけ、identity/binding の増減と
  スコープ変化件数を要約する。
- 対応表（示唆的）: G1→IA-5, IA-5(7), CC6.1, CC6.6／G2→AC-6, CC6.1／G3→AC-6, AC-6(5), CC6.1／G4→IA-5, AC-6, CC6.1／
  G5→IA-5, AC-6, CC6.1／G6→IA-5, CC6.1, CC6.6／G7→AC-6, IA-5, CC6.1／G8→AC-6, AC-6(7), IA-5, CC6.1。
  制御は ID と短い要約タイトルのみ（SOC 2 の基準本文は転記しない）。認証・準拠の主張はしない旨を JSON と MD の両方に明記。
- exit code は常に 0（成果物の生成であり CI ゲートではない。ゲート結果は `findings_summary.exit_code` に記録）。

## D-036 プローブで見つかった検出器のバグ 2 件（新テスト付きで修正）
1. `run:` スクリプト中のシェル変数名 `npm_packages` が npm トークンの形状（`npm_` + 8 文字以上）に一致し G1（と G4）に
   なっていた。npm トークンの形状を実形式 `npm_` + 36 文字に厳格化。
2. `steps.redact_secrets.outcome` の `secrets.outcome` 部分を secrets 参照と誤読し、`unknown:outcome` という identity が
   G5 になっていた。`secrets` の直前が識別子文字・`.`・`-` でないことを要求（コンテキスト名そのものだけを読む）。
回帰テスト: `tests/test_probe_regressions.py`。凍結 dev・dev-ext の採点結果は不変（テストで確認）。

## D-037 プローブのレビューで得た気づき（検出器は変更しない。Phase 3 の検討事項）
- **CODEOWNERS が無いリポジトリでは G4 が全 binding に出る**（modelcontextprotocol/servers で 40 件）。定義上は妥当だが
  根本原因は 1 つ。「CODEOWNERS 不在」を 1 件に集約する表示を検討。
- **テスト用フィクスチャ・例示用の MCP 設定**（caplock の `fixtures/`、`examples/`）も実設定として扱われる。
  `grantlock.policy.json` にパス除外を設ける案。
- **`secrets.*` をすべて資格情報とみなす（D-009）コスト**: エンドポイント URL を入れた secret（OTLP endpoint）が
  G5 になる。名前が資格情報らしくない secret は type=unknown のまま G5 対象から外す案。
- **同一ワークフロー内のジョブ間共有**（gh-aw が生成する `.lock.yml` 等）は仕様どおり G5 だが重要度は低い。
  ワークフロー単位の集約表示を検討。
- 3 リポジトリとも compose / Kubernetes / Terraform のファイルは 0 件で、新面の実地プローブにはなっていない。
  MCP の設定例の多くは README のコードブロックにあり（12 / 11 / 1 ファイル）、読み取り対象外。

## D-038 holdout 採点（Step 8）: NOT RUN と採点ツール
Step 8 実行時点で `~/grantlock-holdout/`（別セッションが作る封印コーパス）が存在しなかったため、採点は **NOT RUN**。
このセッションでは holdout の内容を作っていない・見ていない。採点ツール `python -m grantbench.holdout_score` は用意済み:
- 読み取り専用（lock はメモリ上で生成、`grantbench/lockless.py` と共通）。出力は集計値のみ（ケース ID・パス・component・本文を含まない）。
- `corpus_sha256` を holdout 作成プロンプトの定義（cases/ 以下、POSIX 相対パス文字列のバイト順、path+0x00+bytes+0x00）で
  再計算し manifest と照合。
- 厳格一致と、新面（compose/K8s/Terraform）に限る (class, file) フォールバックの両方を出し、フォールバック件数を明記。
- 適用範囲外（.env の G1/G2/G3/G5/G6、compose の G2/G3 = D-023）は分母から除外し、除外件数を面別に出す。
- GATE 基準 4（G2/G3/G7 各 ≥ 80% かつ平均 ≥ 90%、clean ≤ 5%）を判定。ベースラインも同じコーパスで実測。

## D-039 holdout 採点の結果（GATE 2 確定: FAIL）と見落としパターン
封印 holdout（別セッション作成、88 件、seed 31415926）を `grantbench.holdout_score` で採点。corpus_sha256 は holdout 側の定義で
再計算して manifest と一致、コーパスは読み取り専用のまま（採点前後で更新時刻不変）。数字は `reports/phase2_holdout_scores.json`
（集計値のみ）と `reports/phase2.md`。G2 6/7、G3 5/7、G7 8/8、平均 85.7%、clean 0/16 → 基準 4 不合格。
見落としの型（ケース本文は転記しない）:
- 設計上の欠落: (A) 束縛のない Role/ClusterRole の rules 変更が見えない（D-026 の「Binding 経由でのみ identity を作る」設計）、
  (B) Terraform provider の `var.*` による静的キー指定と assume_role の削除を扱わない、(C) 宣言側（SA の連合 annotation 削除、
  未使用の静的キー Secret）で G6 を出さない、(D) `var.*` の参照・変数宣言を身分として扱わない。
- 慣行差: (E) `.env` を使用側・`.env.example` を宣言側とみなす解釈、(F) 資格情報名の変更＝新 ID、(G) `*` への拡大は G2 でもある、
  (H) 身分の置換は G7 + G8。diff 不一致 4 件はすべて F〜H で説明できる。
プロンプトの指示どおり、採点結果を見た後の検出器の調整はしていない（holdout の意味を保つため）。A〜D は Phase 3 で新テスト付きで
扱い、その再評価には新しい封印 holdout が必要（この holdout は既に結果を見ているため、再採点の数字を合格根拠にしない）。

# Phase 2 修正ラウンド

## D-040 束縛のない Role / ClusterRole を身分にする（盲点 A）
どの RoleBinding / ClusterRoleBinding からも参照されない Role / ClusterRole について、ロール自体を身分
（`kubernetes:role:<ns>/<name>` / `kubernetes:clusterrole:<name>`、component = そのロールの metadata.name、kind `k8s_rbac`）
として inventory に載せ、rules を正規化スコープとして持たせる。rules の拡大は G2、`*` 等は G3 になる。
- 二重計上の回避: 束縛されているロールにはこの身分を作らない（従来どおり subject 側の身分で追跡）。
- 束縛のなかったロールが束縛された場合、ロール身分は inventory から消えるが、ロール自体は定義されたままなので G8 にしない
  （diff の G8 判定で、ロール身分の component が現在も存在すれば休眠扱いしない）。subject 側には D-031 の G2 が出る。
テスト: `tests/test_fix_k8s_unbound_role.py`（実装前に失敗を確認）。

## D-041 provider ブロックの資格情報を第一級の身分にする（盲点 B）
provider ブロック 1 つにつき、静的資格情報（aws: `access_key`/`secret_key`、google: `credentials`/`access_token`、
azurerm: `client_secret` 等）は値がリテラルでも `var.*` 等の式でも 1 つの長期静的身分（`<provider>:terraform:<dir>//provider.<name>[.<alias>].<access_key|credentials|client_secret>`）
として記録する。リテラルなら従来どおり inline（G1、形式分類のみ）、式なら storage=env（値は評価しない）。
連合の形（aws `assume_role` / `assume_role_with_web_identity` ブロック、google `impersonate_service_account`、azurerm
`use_oidc = true` / `use_msi = true`）は ephemeral の federated 身分として記録する。
結果として assume_role → 静的キーへの切替は G6（連合が可能なのに長期静的キー）+ G7（静的キー身分の出現）+ G8（連合身分の休眠）。
テスト: `tests/test_fix_tf_provider.py`。

## D-042 Kubernetes の宣言側 G6（盲点 C）
静的クラウドキー（provider が aws / gcp / azure、type が静的キー種別）を持つ Secret のうち、どのキーも workload から
使われていないものは、Secret の宣言エントリ自体に「連合（IRSA / GKE Workload Identity / Azure Workload Identity）が使えるのに
長期静的キー」の文脈を付ける（→ G6）。さらに、連合 annotation を持たない ServiceAccount と**同じファイル・同じ namespace**に
宣言された未使用の静的キー Secret は、その ServiceAccount にも紐付ける（ServiceAccount の component にも G6）。
- 二重計上の回避: Secret のいずれかのキーを workload が使っていれば、G6 は従来どおり workload にだけ出し、宣言側には出さない。
- 紐付けを同一ファイルに限るのは、namespace 内の無関係な ServiceAccount すべてに G6 を広げないための保守的な規則（ヒューリスティクス）。
テスト: `tests/test_fix_k8s_decl_g6.py`。

## D-043 Terraform の `var.*` 資格情報参照を追跡する（盲点 D）
資格情報らしい名前（D-006）か `sensitive = true` の variable を身分にする: variable ブロックは宣言（kind `terraform`、
component `var.<name>`、storage=env、値は評価しない）、それを `var.<name>` で参照する resource / module ブロックは使用者
（kind `terraform_workload`、component はそのブロックのアドレス）。参照をやめると使用者がいなくなり G8（参照していた
ブロックを指す）、2 つ以上のブロックが同じ資格情報変数を使えば G5。provider ブロックの参照は D-041 の provider 身分で
扱うため使用者として数えない（二重計上の回避）。資格情報らしくない変数（region 等）は対象外。
テスト: `tests/test_fix_tf_var_refs.py`。

## D-044 実ファイルの `.env` は変数の「使用」（解釈差 E の決定）
`.env` と、`.env.<名前>` のうち雛形（example / sample / template / tmpl / dist / default(s) / schema / tpl を含むもの）でない
ファイル（`.env.local`、`.env.production` 等）は、その変数の**使用**として扱い、新しい消費種別 `env_use`（component 名は
相対パス）で binding を作る。雛形は従来どおり宣言 `env_decl`。値は従来どおり読まない（名前だけ）。
- 結果: base で `.env` が使っていた身分が repo で使われなくなれば、G8 は `.env` ファイルを指す。
- **G5 の共有数には `.env` の使用を数えない**（`schemas.SHARING_EXCLUDED_KINDS`）。理由: `.env` はローカル実行・デプロイ環境への
  値の供給経路であり、同じ資格情報を `.env` と MCP サーバ（あるいは `.env` と `.env.production`）が「共有」していても、
  それは同じ消費者に値を渡しているだけで別の構成要素が身分を共有しているわけではない。宣言 env_decl を共有数から外した
  D-013 と同じ扱い。一方 G8 の「まだ使われているか」の判定では `.env` も使用者に数える（`.env` が使っている間は休眠ではない）。
テスト: `tests/test_fix_env_usage.py`（実装前に、使用の継続中は G8 にならないという仕様側の期待に 1 件修正してから失敗を確認）。

## D-045 diff の二重ラベル（Step 6）: 既存の意味論のため変更なし
「既存身分のスコープがワイルドカード/管理者級へ拡大した diff を G3 に加えて G2 もラベルする」は、D-013（正規化スコープ集合の
差分が非空なら G2）により Phase 1 から既にそうなっている（MCP / GHA / K8s / Terraform の全面で確認するテスト
`tests/test_fix_double_label.py` を追加）。凍結 dev・全テストとの競合は無い。
なお開示済み holdout の該当 diff は作成者の期待ラベルが G3 のみのため、この規則を維持する限り不一致のまま（慣行差 G）。
Step 6 の指示はこの不一致を固定する方向であり、diff 正解率の改善には寄与しない。

## D-046 修正ラウンドの結果の扱い
開示済み holdout の到達度（G2 7/7、G3 7/7、G6 8/8、G8 8/8、clean 0/16、diff 4/8）は、その holdout の見落としパターンを見て直した後の
数字であり合否ではない。GATE 2 の判定（FAIL、D-039）は変えない。再ゲートは別作者・別 seed の封印 holdout v2 で行う。
diff の残り 4 件は慣行差（F: 名前変更 = 新身分、G: `*` 拡大は G2 でもある、H: 身分の置換は G7 + G8）。F・G を変えると
固定意味論（身分 = provider + 資格情報名）や Step 6 の指示と矛盾するため変えない。

# GATE 2 再ゲート（holdout v2）

## D-047 採点中の検出器クラッシュは「その事例の失敗」として数える（採点ハーネスのみ変更）
v2 の採点中に GrantLock の `scan()` が例外で停止した。原因は Phase 1 からの潜在バグ: 形式表 `FORMAT_TABLE` の Slack Webhook の
プレフィックス（`https://hooks.slack.com/`、24 文字）がスキーマの prefix 上限（16 文字）を超え、リテラルの Slack Webhook URL を
含む設定でインベントリのスキーマ検証に失敗する。再ゲートの指示（v2 を見た後に検出器を調整しない）に従い**検出器は直さない**。
代わりに採点ハーネス（`grantbench/lockless.py`）だけを変更し、検出器の例外をその事例の失敗として数える: planted は見落とし、
clean は誤検出（クラス `ERROR`）、diff は不正解（予測 `ERROR`）。例外の件数は事例種別ごとに集計して出力する（事例 ID は出さない）。
これは「現行の検出器が CI で落ちる」ことをそのまま失敗として測る保守的な扱い。テスト `tests/test_scoring_errors.py`。
検出器側の修正（prefix の上限と形式表の整合）は Phase 3 の判断に委ねる。

## D-048 holdout v2 の再ゲート結果（GATE 2: FAIL 最終）と原因パターン
封印 holdout v2（別作成者、v1 非参照、seed 60221407、88 件）を修正ラウンド後のコードで採点（読み取り専用、hash 一致、除外 0 件）。
G2 7/8・G3 7/8・G7 8/8・平均 91.7% は基準内だが、clean 誤検出 5/16 = 31.25% で基準 4 不合格。v1 の FAIL 記録は履歴として残す。
原因（パターンのみ。検出器は直していない）:
- **clean 誤検出 5 件・diff 不一致 3 件の共通原因**: D-024 の追補（compose で資格情報らしい名前のキーに秘密でないリテラルが入っていれば
  資格情報参照とみなす）が、パスワードを含まない接続 URL にも適用され、複数 service の共有として G5 になった。鍵ファイルのパス用の規則を
  URL にまで広げた設計の誤り。修正方針案: 値がパスワードなしの URL / ホスト名なら資格情報にしない（MCP の扱いと揃える）。
- 見落とし: (i) Slack Webhook の形式プレフィックスがスキーマ上限を超えて検出器が例外停止（D-047）、(ii) Terraform の入れ子マップ内の
  リテラル、(iii) リモート MCP の HTTP ヘッダによる toolsets 指定（G2・G3 各 1 件）、(iv) Secret ボリュームでマウントした SA 鍵ファイル +
  鍵パスの env（G6）。
v2 の作成者に渡した diff の慣行との食い違いは 0 件（diff 不一致 3 件はすべて上の誤検出の混入）。
v2 は開示済みになったため、これらの修正後の合否判定には新しい封印 holdout（v3）が必要。修正の着手は Phase 3 の進め方と合わせて別途決める。

# 修正ラウンド 2（GATE 2 は FAIL のまま。開示済みコーパスでの再検証）

## D-049 compose: 資格情報参照とみなす値を鍵ファイルのパスに限定する（D-024 追補の絞り込み）
D-024 の追補は「資格情報らしい名前のキーに秘密でないリテラルがあれば外部資格情報への参照」としていたが、パスワードを含まない接続 URL や
ホスト名まで身分化し、複数 service の共有（G5）として誤検出していた（D-048）。次のとおり絞る:
- 参照とみなすのは**鍵ファイルらしいパス**だけ（`/`・`./`・`../`・`~/` で始まる、`/` を含む、または `.json`/`.pem`/`.key` 等の拡張子。`://` を含むものは除く）。
- パスワードを含まない URL と、ホスト名（小文字で、ドットを含むか数値ポート付き。例 `db.internal`、`cache:6379`）は設定値として扱い、
  身分にしない（ホスト名は resources に記録）。ホスト名判定を小文字・ドットまたはポート必須に限ったのは、パスワードらしい文字列を
  取りこぼさないため。単一ラベルの値（例 `redis`）は従来どおりの判定（D-006）に任せる。
- パスワードを含む URL は従来どおり inline（G1、形式 `connection_string_with_password`）。
変更は compose パーサに限る。MCP パーサは資格情報らしい名前のキーに入った秘密でないリテラルを、Phase 1 から（値の形に関係なく）参照として
扱っており、同種の誤検出の余地が残る（このラウンドの対象外。Phase 3 で揃えるか判断）。
テスト: `tests/test_fix2_compose_urls.py`（実装前に 2 件の失敗を確認）。

## D-050 Slack Webhook の形式プレフィックスをスキーマ上限内に収める（D-047 のクラッシュの修正）
`FORMAT_TABLE` の slack_webhook_url の記録プレフィックス `https://hooks.slack.com/`（24 文字）がスキーマ `format.prefix` の上限 16 文字を
超え、リテラルの Webhook URL を含む設定で inventory のスキーマ検証が失敗し `scan()` が例外停止していた。スキーマ上限は引き上げず
（値が紛れ込む余地を広げないため）、**記録する記述子をホスト名 `hooks.slack.com`（15 文字）に変更**した。判定の正規表現は従来どおり
`https://hooks.slack.com/services/` で始まる値。記述子は表上の定数でありパス以降（ワークスペース ID・秘密部分）は含まない。
表全体の不変条件（全プレフィックスがスキーマを満たす・クラスが列挙に含まれる）をテスト `tests/test_fix2_format_prefix.py` で固定。

## D-051 修正ラウンド 2 の再検証結果の扱い
開示済み holdout v2 で clean 0/16・G1 7/8・diff 8/8・G2/G3 7/8・G7 8/8、v1 は変化なし、凍結 dev・dev-ext は完全一致、プローブ件数は不変。
採点スクリプトの `criterion_4_pass: true` は開示済みコーパス上の値であり、GATE 2 の正式判定（FAIL、D-048）は変えない。
合否の再判定は封印 holdout v3 で行う。残る見落としは対象外とした 3 パターン（D-048）のみ。

# Phase 3 準備

## D-052 テストに混入していた holdout v1 由来の識別子を除去（既存テストの変更の透明性記録）
公開前の走査で、修正ラウンド 1 の新規テスト 2 ファイルに、holdout v1 の見落とし分析時に目にした識別子（環境変数名 1 つ、
Terraform の変数名 1 つ、リソース名 1 つ）がそのまま使われていたことが分かった。「holdout のケース本文・ID をリポジトリ側へ
転記しない」規則への違反なので、`tests/test_fix_env_usage.py` と `tests/test_fix_tf_var_refs.py` の該当識別子を中立な名前に置換した
（テストの意図・判定内容は不変。provider 推定が名前の `DB` トークンに依存するため、置換後の変数名にも `db` を含めた）。
既存テストファイルを変更しない原則の例外として記録する。走査対象の語は本記録には書かない。
なお `holdout-planted-G3-01` 形式の ID は、仕様と作成プロンプトに例示された**形式**として採点器のドキュメントと合成テストに
使っているだけで、holdout のケース内容は含まない。
