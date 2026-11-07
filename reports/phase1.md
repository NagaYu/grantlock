# GrantLock Phase 1 報告書

- 日付: 2026-11-07
- 範囲: Phase 1（スキャンコア 3 面、lock / check、GrantBench dev 生成器、採点ハーネス、CLI/SARIF）
- リポジトリ: ローカル git のみ（push・公開なし）
- 再現手順:
  ```bash
  python3 -m pytest
  python3 -m grantbench.generator --split dev --out bench/dev
  python3 -m grantbench.score --corpus bench/dev --out reports/phase1_scores.json
  ```
- dev コーパス: 120 件、seed 20261107、`corpus_sha256 = 806d821b43fe1813f21d0c7dded45e2b5871b50426a012fd791dbf5627aeae76`
  （別プロセスで 2 回生成して同一ハッシュを確認。`bench/dev.manifest.json` にケース一覧を記録）

## 結論

**GATE 1: PASS（自己判定）。** 基準 1〜6 をすべて満たした。ただし基準 5 の数値（dev で全クラス
recall 100%、clean 誤検出 0%）は、生成器と検出器を同じ作者が同じ SPEC から書いた合成コーパス上での
**自己整合性の確認**であり、実環境での検出力の証拠ではない（「解釈上の注意」参照）。ベースラインは
初版時点では未導入で NOT RUN だったが、追記（下記「ベースライン実測の追記」）で Homebrew から
gitleaks 8.30.1 / trufflehog 3.99.8 を導入して実測した: G1 recall は gitleaks 6/10・trufflehog 7/10、
G2–G8 は両者とも 0/10（G2–G8 の 70 ケースで 1 件も報告なし）、clean 誤検出は両者 0/24。

## GATE 1 自己判定表

| # | 基準 | 結果 | 根拠 |
|---|---|---|---|
| 1 | pytest 全件 green（件数明記） | **PASS** | 264 passed / 0 failed（内訳は下表） |
| 2 | G1–G8 すべてに分類の専用テスト、dev に各クラス 10 件の planted | **PASS** | `tests/test_diff.py` に G1:3 / G2:5 / G3:4 / G4:2 / G5:3 / G6:3 / G7:3 / G8:3 件の専用テスト。dev manifest の `planted_by_class` が G1–G8 各 10（`test_counts` で検証） |
| 3 | 秘密値がロックファイル・findings・フィクスチャ期待値に現れないことを機械的に確認 | **PASS** | `tests/secret_guard.py` がダミー秘密（`FAKE` を含む）について値そのもの・プレフィックス除去後の本体・md5/sha1/sha256/sha512・base64 の不在を assert。MCP/GHA/.env パーサ出力、inventory、lockfile、findings、SARIF、CLI 出力、採点結果、ベースライン出力の解析結果に適用。ベンチでは生成時に植えた全ダミー値が snapshot に存在し、case.json / manifest / grantlock.json に存在しないことを検証（`test_fixture_secrets_are_fake_and_never_in_expectations`）。`.env` パーサは値を変えても出力が不変であることを性質テストで確認 |
| 4 | 生成器が決定的、holdout 拒否テストが通る | **PASS** | `test_deterministic`（2 回生成で corpus_sha256 とファイル集合が一致）。holdout: 環境変数なし／値が `"1"` 以外／リポジトリ内出力（env あり）／リポジトリ直下をすべて拒否、`generate("holdout")` が何も書かないこと、CLI が exit 2 になることを検証。holdout は生成していない |
| 5 | G2/G3/G7 の dev recall ≥ 80%、clean 誤検出 ≤ 5%、ベースライン同クラス recall 併記 | **PASS** | G2 100% / G3 100% / G7 100%、clean 誤検出 0/24 = 0%。ベースライン同クラス recall（実測）: gitleaks・trufflehog とも G2 / G3 / G7 = 0/10。下の採点表参照 |
| 6 | スキャンコアにネットワーク呼び出しがない | **PASS** | `tests/test_no_network.py`: `grantlock/` 全 .py の import を AST で検査（socket/ssl/http/urllib.request/requests/httpx/aiohttp/subprocess 等を禁止、urllib は `urllib.parse` のみ）。さらに socket 系関数を例外に差し替えた状態で scan → lock → check が完走 |

## 採点結果

### クラス別 recall（planted、ケース単位・厳格判定、各 10 件）

| class | GrantLock | gitleaks | trufflehog |
|---|---|---|---|
| G1 インライン秘密値 | 10/10 = **100%** | 6/10 = 60% | 7/10 = 70% |
| G2 スコープ追加 | 10/10 = **100%** | 0/10 = 0% | 0/10 = 0% |
| G3 ワイルドカード/管理者級 | 10/10 = **100%** | 0/10 = 0% | 0/10 = 0% |
| G4 所有者なし | 10/10 = 100% | 0/10 = 0% | 0/10 = 0% |
| G5 共有 | 10/10 = 100% | 0/10 = 0% | 0/10 = 0% |
| G6 長期静的キー | 10/10 = 100% | 0/10 = 0% | 0/10 = 0% |
| G7 未宣言の新規 ID | 10/10 = **100%** | 0/10 = 0% | 0/10 = 0% |
| G8 休眠 | 10/10 = 100% | 0/10 = 0% | 0/10 = 0% |

項目単位 recall（G5 等は 1 ケースに 2 項目）もすべて 100%。ベースラインは gitleaks 8.30.1
（`detect --no-git --redact`）と trufflehog 3.99.8（`filesystem --no-verification --no-update`、
プロバイダへの検証通信なし）で実測し、出力は (file, rule) 以外を解析時に破棄した。G2–G8 の 0/10 は
ハーネスの規則（値スキャナは G1 のみ判定）による記録だが、別途確認したところ両ツールとも
G2–G8 の 70 ケースで**1 件も finding を出していない**（ファイル一致以前に無反応）ため、0 は実測とも一致する。

### clean 誤検出率・diff 分類正解率

| 指標 | GrantLock | gitleaks | trufflehog |
|---|---|---|---|
| clean 誤検出（GrantLock: G クラスの finding / ベースライン: 何らかの finding が 1 件でもあるケース） | 0/24 = **0%** | 0/24 = 0% | 0/24 = 0% |
| diff_pair 分類正解率（予測クラス集合の完全一致） | 16/16 = **100%** | N/A | N/A |

diff_pair の内訳: ラベル空の良性変更 3 件（文言変更、スコープ縮小、サーバ名変更 = binding の移動）、
単一クラス 7 件、複数クラス 6 件（例: OIDC → 静的キー置換 = G6+G7+G8、job 名変更 = G7+G8、
既存の評価キーを新ジョブで再利用 = G5+G7）。

参考（採点対象外）: planted ケースで対象以外のクラスが同時に出た件数は G2:6, G7:24, G8:12。
いずれも変異の仕様上の帰結（例: 静的キーへの置換で新 identity = G7、旧 OIDC role = G8）で、
DECISIONS D-014 のとおり許容している。

### 解釈上の注意（数値を過大評価しないために）

1. **同一作者バイアス**: 生成器の変異とラベル、検出器の意味論は同じ SPEC/DECISIONS から同じ作者が書いた。
   dev 100% は「実装が SPEC どおりに動く」ことの確認であって、未知の書き方に対する汎化の証拠ではない。
2. **合成コーパス**: 実在の MCP 設定・ワークフローの形を模しているが、テンプレート由来のため書き方の
   多様性（anchors、composite action、reusable workflow、matrix、monorepo 構成など）は限られる。
3. **dev は確認後に検出器を変更していない**が、開発中のパーサ単体テストは同じ作者の想定に基づく。
   holdout は別 seed だけでなく、別作者（または別エージェント）が書いたテンプレート・変異で作るべき。
4. clean の near-miss（GITHUB_HOST の URL、プロキシ URL、TOKEN_CACHE_DIR、`permissions: {}`、
   PUBLISHABLE_KEY、`${input:}` 等）は採点前に固定した。

## ベースライン実測の追記（2026-11-07、初版後）

オーナーの承認を得て、Homebrew の公式 tap（homebrew/core）から gitleaks 8.30.1 と trufflehog 3.99.8 を
導入し、同じ dev コーパス（corpus_sha256 不変）で `python3 -m grantbench.score` を再実行した。GrantLock の
数値は初版と同一。採点・コーパス・期待ラベルは変更していない。

G1 のケース別結果（どちらかが取りこぼしたもの）:

| case | 変異 | gitleaks | trufflehog | 考察 |
|---|---|---|---|---|
| G1-02, G1-09 | 接続文字列に埋め込んだパスワード | 検出なし | Postgres で検出 | gitleaks の既定ルールは URL 内パスワードを拾わない |
| G1-04 | ワークフロー step env の Anthropic 形キー | 検出なし | 検出なし | 下記の注意 1 |
| G1-05 | `run:` の curl に Slack bot トークン | curl-auth-header で検出 | 検出なし | 下記の注意 1 |
| G1-06 | CLI 引数の OpenAI 形キー | 検出なし | 検出なし | 下記の注意 1 |

ベースライン数値の注意:

1. **ダミー秘密の形式がベースラインに不利な可能性**: 生成器のダミーは `sk-FAKE` + 英数字 40 字のように
   プレフィックスだけを模しており、実在形式の細部（OpenAI キーの固定マーカー、Anthropic キーの
   `sk-ant-api03-` 形と長さ、Slack トークンの桁構成など）を再現していない。gitleaks / trufflehog の
   ルールは実形式に厳密なため、G1 の取りこぼしの一部はツールの弱さではなくコーパスの非現実性による
   可能性が高い。採点後にコーパスを変えると後付け調整になるため今回は変更せず、Phase 2 で
   「実形式に忠実な（ただし明らかに偽の）ダミー」に改めて再測定することを推奨する。
2. GrantLock の G1 は自前の形状表とキー名規則の両方で判定するため、このダミー形式の影響を受けにくい。
   これは GrantLock の G1 優位を示すものではない（同一作者バイアス、上記 1）。
3. G2–G8 で 0 なのは、これらの変異が値を含まない（権限・所有者・共有・休眠などの構造変化）ため。
   値スキャナとの比較で意味があるのは「値なしクラスを見られるか」であり、ここは設計どおりの差。

## 作ったもの（ステップごと）

| Step | 内容 | 主なファイル | テスト |
|---|---|---|---|
| 0 | 雛形（pyproject、パッケージ、SPEC/STATUS/DECISIONS） | `pyproject.toml`, `grantlock/__init__.py` | `test_smoke.py` |
| 1 | バージョン付き JSON スキーマ（inventory / lock / findings / policy、閉じたオブジェクト）と身分モデル表（provider 推定、資格情報名判定、type 分類、形式分類、管理者級判定） | `grantlock/schemas.py`, `grantlock/model.py` | `test_schemas.py`, `test_model.py` |
| 2 | MCP 設定パーサ（`mcpServers`/`servers`、JSONC、env/headers/args/URL クエリ/oauth、inline は形式分類のみ、委任 OAuth、スコープ源） | `grantlock/parsers/mcp.py`, `parsers/common.py` | `test_mcp_parser.py` |
| 3 | GHA パーサ（permissions 正規化・暗黙デフォルト区別、secrets 参照、OIDC 連合検出と識別子の吸収、静的キー、inline、`on:` の YAML 1.1 対策） | `grantlock/parsers/gha.py` | `test_gha_parser.py` |
| 4 | .env パーサ（名前のみ、値非依存、複数行引用の読み飛ばし） | `grantlock/parsers/dotenv.py` | `test_dotenv_parser.py` |
| 5 | `scan()`（ファイル探索、symlink 非追跡、除外ディレクトリ）と CODEOWNERS / 宣言 owner 解決 | `grantlock/inventory.py`, `grantlock/owners.py` | `test_inventory.py`, `test_owners.py` |
| 6 | `lock()`（決定的順序、正規化シリアライズ、evidence 除去、タイムスタンプなし）と read/検証 | `grantlock/lockfile.py` | `test_lockfile.py` |
| 7 | `diff()` と G1–G8 分類、change（introduced/unchanged/removed）、drift、重大度ポリシーと本番ヒューリスティクス、`check()`（書き込みなし） | `grantlock/diff.py`, `policy.py`, `check.py` | `test_diff.py` |
| 8 | GrantBench 生成器（テンプレート、near-miss、各クラス 6〜8 変異、diff_pair 16 種、case スキーマ、holdout ガード） | `grantbench/templates.py`, `mutations.py`, `generator.py` | `test_bench_generator.py` |
| 9 | 採点ハーネス（GrantLock 自己採点、ベースライン実行・突き合わせ・NOT RUN 経路） | `grantbench/score.py` | `test_bench_score.py` |
| 10 | CLI（`scan`/`lock`/`check`、text/json/sarif）、SARIF 2.1.0、README、本報告書、ネットワーク不在テスト | `grantlock/cli.py`, `sarif.py`, `README.md` | `test_cli.py`, `test_no_network.py` |

## テスト総数と内訳

合計 **264 passed**（`python3 -m pytest`、約 11 秒）。

| ファイル | 件数 | 対象 |
|---|---|---|
| test_model.py | 97 | provider/type/名前判定・形式分類・管理者級・lifespan（パラメタ化） |
| test_diff.py | 35 | G1–G8 専用テスト、重大度ポリシー、check 非書き込み、決定性 |
| test_gha_parser.py | 20 | permissions 正規化、OIDC、静的キー、inline、警告 |
| test_owners.py | 17 | CODEOWNERS パターン、最後一致、無所有規則 |
| test_bench_generator.py | 16 | 件数、決定性、スキーマ、holdout 拒否、ダミー秘密 |
| test_mcp_parser.py | 13 | 参照/inline、JSONC、OAuth、スコープ、値非混入 |
| test_schemas.py | 12 | 3 文書 + policy のスキーマ |
| test_lockfile.py | 12 | 決定性、行移動耐性、往復、不正 lock 拒否 |
| test_bench_score.py | 11 | 採点計算、厳格判定、NOT RUN、ベースライン解析、ハーネス対照 |
| test_inventory.py | 11 | 3 面統合、owner、共有材料、symlink、ネットワーク |
| test_cli.py | 9 | lock/check/scan、exit code、SARIF、非書き込み |
| test_dotenv_parser.py | 7 | 名前のみ、値非依存 |
| test_no_network.py | 3 | import の静的検査、socket 無効化下での全経路 |
| test_smoke.py | 1 | パッケージ import |

## 逸脱・未実装・判断に迷った点（DECISIONS.md 参照）

仕様と衝突しうる、または仕様の解釈を要した点:

- **D-003** inventory は (identity, component) の binding 単位。`identity_id` が provider+名前から決まる以上、
  共有（G5）は同じ ID の複数エントリで表す。単数の `component` フィールドは各エントリで保持。
- **D-009** GitHub Actions の暗黙 `GITHUB_TOKEN` はジョブごとの identity（`github:GITHUB_TOKEN@<file>#<job>`）。
  provider+名前だけで作るとワークフローが 2 本あるだけで G5 になるため。
- **D-009** G6 の「連合が可能な文脈」をプラットフォーム可用性（GHA から AWS/GCP/Azure/PyPI/npm への OIDC）で判定。
  仕様の例（同一ワークフローで OIDC が使えるのに静的キー）より広い。MCP のクラウド静的キーも SSO/ADC 等の
  短期化が可能な文脈として扱う。
- **D-010（最も仕様解釈に踏み込んだ点）** 本番 G3 が既にコミット済み lock に記録されている（= 人間がレビュー済み）
  場合は critical ではなく warning を上限とした。新たに導入された本番 G2/G3/G7 は既定どおり critical。
  「lock の差分コミットがレビュー面」という仕様に沿う解釈だが、「本番の G3 = critical」を字義どおりに読む立場とは
  異なる。ポリシーで critical 固定にする選択肢を Phase 2 で検討。
- **D-011** `.env` は値を読まないため、コミットされた `.env` の実値は G1 にならない（仕様の帰結）。
- **D-012** 「宣言された所有者」は `grantlock.policy.json` の `declared_owners` で表現。
- **D-013** 既知だったスコープが未知になる変化（明示 permissions の削除 → 暗黙デフォルト、toolsets 指定削除）を G2 とした。
  分類外の差分は `drift` に記録し exit code に影響させない。
- lock は `evidence`（行番号）を落とす（行移動で lock が揺れないように）。
- 依存: PyYAML（D-001）と jsonschema（D-002）。

未実装（Phase 1 の範囲外として明示）:

- `secrets: inherit` の列挙（警告のみ）、再利用ワークフロー/composite action の解決、`vars.*` の扱い、
  リポジトリ/組織設定に依存する暗黙デフォルト権限の実値。
- `.claude.json` のプロジェクト別ネスト `mcpServers`、ユーザーホームの MCP 設定（リポジトリ外）。
- 行番号はテキスト検索による近似（YAML のマーク情報は使っていない）。
- 本番判定は命名ヒューリスティクスのみ（GitHub environment の保護ルールは見ない）。

## Phase 2 への引き継ぎ事項

1. **新しい面**: docker compose（`environment:`/`secrets:`/`env_file`）、Kubernetes（Secret 参照、ServiceAccount、
   RBAC の ClusterRole/verbs `*`、IRSA/Workload Identity 注釈）、Terraform（IAM ポリシーの Action/Resource `*`、
   OIDC プロバイダ、`aws_iam_access_key` 等の静的キー資源）。model の FEDERATION_TABLE と管理者級リストの拡張が必要。
2. **証拠パック**: check の結果を、lock の差分・findings・判定根拠（production evidence、CODEOWNERS 規則）・
   スキーマ版をまとめた監査用アーティファクトとして出力（値なし）。SARIF の properties を拡張済みなので起点にできる。
3. **holdout**: 生成器の holdout モードは実装済み・未実行。実行は `GRANTLOCK_ALLOW_HOLDOUT=1` かつリポジトリ外のみ。
   同一作者バイアスを避けるため、holdout 用テンプレートと変異は別作者（別エージェント）が SPEC だけを見て書き、
   GrantLock 開発側はその中身を見ない運用を推奨。
4. **ベースライン比較の公平化**: 実測済み（G1: gitleaks 6/10、trufflehog 7/10）。ただしダミー秘密が実形式に
   忠実でないため G1 比較は不公平の可能性がある。実形式に忠実な偽ダミーへ改め、holdout で再測定する。
5. **仕様判断の確認**: D-010（lock 済み G3 の重大度上限）、D-009（G6 の判定範囲、GITHUB_TOKEN の ID 形）、
   D-011（`.env` の値を読まない方針と G1 の盲点）についてオーナー判断を仰ぐ。
6. 実リポジトリ（公開 OSS のエージェント構成）での誤検出調査。合成 dev の 0% を実環境の数字と取り違えないこと。
