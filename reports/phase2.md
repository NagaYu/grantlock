# GrantLock Phase 2 報告書

- 日付: 2026-11-07
- 範囲: 新 3 面（docker-compose / Kubernetes / Terraform）、証拠パック `grantlock evidence`、GrantBench `dev-ext`、
  実リポジトリ誤検出プローブ、holdout 採点（→ NOT RUN）
- リポジトリ: ローカル git のみ（push・公開なし）。Phase 3（公開）には進んでいない
- 再現:
  ```bash
  python3 -m pytest
  python3 -m grantbench.generator --split dev-ext --out bench/dev-ext
  python3 -m grantbench.lockless --corpus bench/dev-ext --out reports/phase2_dev_ext_scores.json
  python3 -m grantbench.probe --workdir <リポジトリ外のディレクトリ> --out reports/phase2_probe.json
  python3 -m grantbench.holdout_score --corpus ~/grantlock-holdout --out reports/phase2_holdout_scores.json
  ```
- 追記（2026-11-07）: 別セッションが作成した封印 holdout（`~/grantlock-holdout/`、seed 31415926、88 件）を採点し、GATE 2 を確定

## 結論

**GATE 2 最終判定: FAIL（holdout v2 による再ゲートでも不合格）。** v2 では見出しクラスの recall は基準を満たした
（G2 7/8 = 87.5%、G3 7/8 = 87.5%、G7 8/8、平均 91.7%）が、**clean 誤検出が 5/16 = 31.25%（基準 ≤ 5%）**で不合格。
誤検出 5 件はすべて同一の原因（パスワードを含まない接続 URL を資格情報参照として扱う compose の規則）による。詳細は
「再ゲート（holdout v2）」。以下は v1 による初回判定の記録（履歴として残す）。

**初回判定（holdout v1）: FAIL。** 基準 1・2・3・5・6・7 は満たしたが、基準 4（holdout の見出し基準）を満たさなかった:
G2 6/7 = 85.7%、G3 **5/7 = 71.4%（< 80%）**、G7 8/8 = 100%、3 クラス平均 **85.7%（< 90%）**。clean 誤検出は 0/16 で基準内。
見落としはすべて Phase 2 で追加した新面（Kubernetes / Terraform）と `.env` の解釈差に集中し、Phase 1 の面（MCP /
GitHub Actions）は holdout でも全件検出した。詳細は「holdout 結果」。基準を下げる書き換えはしていない。

（初版の判定は「PARTIAL（holdout 未実施）」だった。holdout 作成後に採点して FAIL に確定した。）

dev-ext の数値（適用可能な全クラス 100%、clean 誤検出 0%）は、Phase 1 と同じく**生成器と検出器を同じ作者が書いた
合成コーパス上の自己整合性確認**であり、実環境での検出力の証拠ではない。

## GATE 2 自己判定表

| # | 基準 | 結果 | 根拠 |
|---|---|---|---|
| 1 | pytest 全件 green（総数）、Phase 1 の 264 件が未変更で含まれる | **PASS** | **344 passed**。Phase 1 のテストファイル・ヘルパ・フィクスチャは Phase 1 最終コミット（`ba6547f`）から差分ゼロ（`git diff --stat` が空）で、その 14 ファイルだけを実行して 264 passed |
| 2 | `bench/dev-frozen/` が無編集で、再採点で Phase 1 の数字を再現 | **PASS** | Step 0 で `bench/dev/` をコピーし corpus_sha256 = `806d821b…` を記録・コミット（D-019）。`test_frozen_dev_archive_unchanged` がハッシュ一致を、`test_frozen_dev_rescore_reproduces_phase1_numbers` が現行コードでの再採点 = 全クラス 10/10・clean 0/24・diff 16/16 と、採点後もハッシュ不変であることを毎回検証 |
| 3 | dev-ext: 適用可能クラスごとに recall ≥ 80%、clean ≤ 5%、ベースライン併記 | **PASS** | 全 8 クラス 6/6（100%）、clean 0/12（0%）、diff 8/8。ベースラインは下表（実測） |
| 4 | holdout: G2/G3/G7 各 ≥ 80% かつ平均 ≥ 90%、clean ≤ 5% | **FAIL（v1・v2 とも）** — v2: G2 87.5%・G3 87.5%・G7 100%・平均 91.7% は満たすが clean 31.25% で不合格。以下は v1 の値: | G2 6/7（85.7%）、G3 5/7（71.4%）、G7 8/8（100%）、平均 85.7%、clean 0/16（0%）。G3 が 80% 未満、平均が 90% 未満。適用範囲外（compose × G2/G3、D-023）の 2 項目は分母から除外済み |
| 5 | 証拠パックが自スキーマで検証可能、秘密値なしを機械確認、IA-5 / CC6 対応表あり | **PASS** | スキーマ `grantlock.evidence` 1.0（閉じたオブジェクト）で検証。`secret_guard` を JSON と Markdown の両方に適用（Phase 1 フィクスチャのダミーと、実形式ダミー入り compose）。対応表は G1–G8 × IA-5 / IA-5(7) / AC-6 / AC-6(5) / AC-6(7) / CC6.1 / CC6.6、「示唆的マッピング・準拠を主張しない」旨を JSON と MD に明記 |
| 6 | スキャンコアにネットワーク呼び出しなし（AST 検査が新モジュールにも及ぶ） | **PASS** | `test_no_network.py`（Phase 1、`grantlock/` 配下を再帰走査）が新パーサ・evidence を含む全 .py を検査。新面専用の AST テストと、socket 無効化下での scan → lock → check も追加。ネットワークはプローブの clone（`grantbench/probe.py`、コア外）だけ |
| 7 | プローブ: 3 リポジトリの findings レビュー結果（件数と分類） | **PASS** | 下表。全 87 件をレビューし、初回実行で見つかった誤検出 4 件は検出器バグとして新テスト付きで修正（D-036） |

## 採点結果: dev-ext（新 3 面、68 件、seed 20261121）

corpus_sha256 = `0f5582ee1642557f779b93444f6c5653f15cb92359aa6bcfc1d37352c0244a8d`（2 回生成で一致）。
生成器・変異・期待ラベルは**採点前にコミット**（Step 5a）。ダミー秘密は実形式（D-018 / D-033）。

### クラス別 recall（planted、厳格一致、各 6 件）

| class | GrantLock | gitleaks 8.30.1 | trufflehog 3.99.8 |
|---|---|---|---|
| G1 インライン秘密値 | 6/6 = 100% | 5/6 = 83% | 6/6 = 100% |
| G2 スコープ追加 | 6/6 = 100% | 0/6 | 0/6 |
| G3 ワイルドカード/管理者級 | 6/6 = 100% | 0/6 | 0/6 |
| G4 所有者なし | 6/6 = 100% | 0/6 | 0/6 |
| G5 共有 | 6/6 = 100% | 0/6 | 0/6 |
| G6 長期静的キー | 6/6 = 100% | 0/6 | 0/6 |
| G7 未宣言の新規 ID | 6/6 = 100% | 0/6 | 0/6 |
| G8 休眠 | 6/6 = 100% | 0/6 | 0/6 |

面別の内訳（GrantLock）: compose G1/G4/G5/G6/G7/G8 各 2/2、Kubernetes G2・G3 各 3/3、他クラス各 2/2、
Terraform G2・G3 各 3/3、他クラス各 2/2。compose の G2/G3 は適用対象外（D-023）。

ベースラインの G2–G8 の 0 は、G2–G8 の 42 ケースで両ツールとも **finding を 1 件も出さなかった**実測と一致する。

### clean 誤検出率・diff 分類正解率

| 指標 | GrantLock | gitleaks | trufflehog |
|---|---|---|---|
| clean 誤検出 | 0/12 = 0% | 0/12 = 0% | 0/12 = 0% |
| diff_pair 正解率 | 8/8 = 100%（良性 3 件を含む） | N/A | N/A |

### G1 の公平性（D-018 の検証）

| コーパス | ダミー形式 | gitleaks G1 | trufflehog G1 |
|---|---|---|---|
| dev（Phase 1） | 接頭辞のみの模倣 | 6/10 | 7/10 |
| dev-ext（Phase 2） | 実形式（長さ・文字種・固定マーカー部）+ `FAKE` | 5/6 | 6/6 |

実形式にしたことで gitleaks の Anthropic / OpenAI / Slack / AWS ルール、trufflehog の各検出器が一致するようになり、
ベースラインの G1 は改善した。gitleaks の唯一の取りこぼしは接続文字列内のパスワード（Phase 1 と同じ型）。
D-018 の「dev のダミー形式がベースラインに不利だった」仮説を支持する結果。

### 凍結 dev の再採点（基準 2）

`bench/dev-frozen/`（無編集）を現行コードで採点: 全クラス 10/10、clean 0/24、diff 16/16（Phase 1 と同一）。

## holdout 結果

別セッション（GrantLock のリポジトリを見ていない）が作成した封印コーパス。88 件（planted 64 = G1–G8 各 8、clean 16、
diff_pair 8）。採点は `grantbench/holdout_score.py`（読み取り専用、lock はメモリ上で生成）。holdout 側の定義で再計算した
corpus_sha256 は manifest と**一致**。採点前後でコーパスのファイル更新時刻は不変、`grantlock.json` は書き込んでいない。
本節には数字とパターンの記述だけを書き、ケースの本文・ファイル名・中身は転記しない。

### クラス別 recall（planted、厳格一致）

| class | GrantLock | 除外なしの場合 | gitleaks 8.30.1 | trufflehog 3.99.8 |
|---|---|---|---|---|
| G1 | 8/8 = 100% | 8/8 | 4/8 = 50% | 4/8 = 50% |
| G2 | **6/7 = 85.7%** | 6/8 = 75% | 0/8 | 0/8 |
| G3 | **5/7 = 71.4%** | 5/8 = 62.5% | 0/8 | 0/8 |
| G4 | 8/8 = 100% | 8/8 | 0/8 | 0/8 |
| G5 | 8/8 = 100% | 8/8 | 0/8 | 0/8 |
| G6 | 3/8 = 37.5% | 3/8 | 0/8 | 0/8 |
| G7 | **8/8 = 100%** | 8/8 | 0/8 | 0/8 |
| G8 | 5/8 = 62.5% | 5/8 | 0/8 | 0/8 |

- 適用範囲外として分母から除外したのは compose × G2 と compose × G3 の 2 項目（D-023、holdout 作成前にコミット済みの規則）。
  「除外なし」は参考値で、GATE 判定には使っていない。
- 新面に限る (class, file) のフォールバック一致は 0 件（命名規則の差による取りこぼしは無かった）。
- ベースラインの G2–G8 は構造上の 0（値スキャナ）。

### clean 誤検出・diff 正解率

| 指標 | GrantLock | gitleaks | trufflehog |
|---|---|---|---|
| clean 誤検出 | 0/16 = 0% | 0/16 = 0% | 0/16 = 0% |
| diff_pair 正解率（厳格） | 4/8 = 50% | N/A | N/A |

### GATE 基準 4 の判定

| 条件 | 値 | 判定 |
|---|---|---|
| G2 ≥ 80% | 85.7% | 満たす |
| G3 ≥ 80% | 71.4% | **満たさない**（7 件中 2 件の見落とし） |
| G7 ≥ 80% | 100% | 満たす |
| 3 クラス平均 ≥ 90% | 85.7% | **満たさない**（3 クラス計 21 件中 3 件の見落とし。許容は最大 2 件） |
| clean 誤検出 ≤ 5% | 0% | 満たす |

→ **基準 4: FAIL、GATE 2: FAIL。**

### dev との乖離の分析（パターンのみ）

dev / dev-ext では全クラス 100% だった。holdout では見落とし 13 項目（planted）と diff 不一致 4 件が出た。
面別に見ると、Phase 1 の面（MCP 13/13、GitHub Actions 16/16）と compose（7/7）は全件検出し、見落としは
Kubernetes（G2 0/1、G3 0/2、G6 0/2）、Terraform（G6 0/3、G8 0/1）、`.env`（G8 0/2）に集中した。

**検出の設計上の欠落**（GrantLock 側の盲点。今回は修正していない）:

| パターン | 影響 | 原因 |
|---|---|---|
| A. どの Binding からも参照されていない Role / ClusterRole の rules を広げる・`*` にする | G2 1 件、G3 2 件（**GATE 不合格の直接原因**） | RBAC のスコープを Binding 経由で ServiceAccount 等に付けたときだけ identity を作る設計（D-026）。束縛のないロールは inventory に現れず、変更が見えない。独立作成者はロール定義そのものを「付与」とみなした |
| B. Terraform の provider ブロックを assume_role（連合）から `access_key` / `secret_key = var.*` の静的キーへ切り替える | G6 3 件 | provider ブロックはリテラル値だけを読む（D-028）。変数参照の静的キー指定と、assume_role の削除（連合の喪失）をどちらも身分として扱っていない |
| C. ServiceAccount から連合 annotation（IRSA）を外し、同じファイルに静的 AWS キーの Secret を追加（それを使う workload は無い） | G6 2 件（G7 は検出） | G6 を「静的キーを**参照する workload**」にだけ出す設計（D-026）。宣言側（SA・Secret）では G6 を出さず、SA の federated → 非 federated の変化は分類外の drift |
| D. Terraform のリソースが `var.*` で参照していた資格情報変数の参照をやめた（変数宣言は残る） | G8 1 件 | `var.*` の参照・変数宣言を身分として扱わない（D-028） |

**慣行差**（意味論の解釈の違い。検出バグではないと判断）:

| パターン | 影響 | 説明 |
|---|---|---|
| E. `.env` から変数名を消し、`.env.example` に宣言だけ残る | G8 2 件 | 独立作成者は `.env` を「使用側」、`.env.example` を「宣言側」とみなした。GrantLock は `.env*` をすべて宣言面（値を読まない名前だけの面、D-011 / D-013）として扱うため、消費者の消失（G8）にならない |
| F. diff: 資格情報の変数名だけを変える（作成者は良性） | 期待 [] → 予測 G7 + G8 | identity_id は provider + 資格情報名から決まる（SPEC §2）。名前の変更は新 ID（G7）と旧 ID の休眠（G8）になる。D-009 のジョブ改名と同じ構造 |
| G. diff: ポリシーを `*` に広げる | 期待 G3 → 予測 G2 + G3（2 件） | 正規化スコープ集合の差分が非空なので G2 も成立（D-013）。作成者は G3 のみを期待 |
| H. diff: 連合から静的キーへの切替、インラインのリテラル資格情報の追加 | 期待に G7 / G8 が無い（2 件） | 新しい資格情報は新 ID（G7）、使われなくなった連合ロールは休眠（G8）になる身分モデル上の帰結 |

diff 不一致 4 件はすべて慣行差（F・G・H）で説明でき、予測は期待ラベルを包含する形（F を除く）だった。慣行差を許容した場合の
参考値は 8/8 だが、GATE は planted の G2/G3/G7 だけで判定するため合否には影響しない。planted の見落とし 13 項目のうち
慣行差は E の 2 項目で、残り 11 項目（A・B・C・D）は検出の設計上の欠落。

**dev 100% と holdout の乖離の原因**: dev-ext の変異は、作者（＝検出器の作者）が「Binding のあるロール」「静的キーを使う
workload」「リテラルの provider キー」という検出器の想定どおりの形で植えていた。独立作成者は同じクラスを、束縛のない
ロール・宣言側の変更・変数経由の指定という別の形で植えた。同一作者バイアス（Phase 1 報告書で警告した点）が、新面で
実際に効いていたことになる。

## 再ゲート（holdout v2）

修正ラウンド（`reports/phase2-fix.md`）の後、v1 とは別の作成セッション（GrantLock も v1 コーパスも見ていない）が作った封印 holdout v2
（88 件: planted 64 = G1–G8 各 8、clean 16、diff_pair 8）で再判定した。v2 の作成者には diff の期待ラベルの慣行（名前変更 = G7 + G8、
`*` への拡大 = G2 + G3、身分の置換 = G7 + G8 など）を事前に渡している。採点は読み取り専用で、holdout 側の定義で再計算した
corpus_sha256 は manifest と一致、採点前後でコーパスの更新時刻は不変。基準 4 のバーは v1 と同一。適用範囲外として除外した項目は
**0 件**（v2 には compose × G2/G3 や .env × G1/G2/G3/G5/G6 の項目が無かった）。

採点中に GrantLock の `scan()` が planted 1 件で例外停止した（Phase 1 からの潜在バグ: Slack Webhook の形式プレフィックスがスキーマの
上限を超える）。再ゲートの規則に従い検出器は直さず、採点ハーネスだけを変えて**例外をその事例の失敗（見落とし）として数えた**（D-047）。

### クラス別 recall（planted、厳格一致）

| class | GrantLock | gitleaks 8.30.1 | trufflehog 3.99.8 |
|---|---|---|---|
| G1 | 6/8 = 75%（うち 1 件は例外停止） | 5/8 = 62.5% | 5/8 = 62.5% |
| G2 | **7/8 = 87.5%** | 0/8 | 0/8 |
| G3 | **7/8 = 87.5%** | 0/8 | 0/8 |
| G4 | 8/8 = 100% | 0/8 | 0/8 |
| G5 | 8/8 = 100% | 0/8 | 0/8 |
| G6 | 7/8 = 87.5% | 0/8 | 0/8 |
| G7 | **8/8 = 100%** | 0/8 | 0/8 |
| G8 | 8/8 = 100% | 0/8 | 0/8 |

新面限定の (class, file) フォールバックで追加一致した件数は 0。

### clean 誤検出・diff 正解率

| 指標 | GrantLock | gitleaks | trufflehog |
|---|---|---|---|
| clean 誤検出 | **5/16 = 31.25%** | 0/16 | 0/16 |
| diff_pair 正解率（厳格） | 5/8 = 62.5% | N/A | N/A |

### GATE 基準 4（v2）の判定

| 条件 | 値 | 判定 |
|---|---|---|
| G2 ≥ 80% | 87.5% | 満たす |
| G3 ≥ 80% | 87.5% | 満たす |
| G7 ≥ 80% | 100% | 満たす |
| 3 クラス平均 ≥ 90% | 91.7% | 満たす（24 件中見落とし 2 件） |
| clean 誤検出 ≤ 5% | 31.25% | **満たさない** |

→ **基準 4（v2）: FAIL、GATE 2: FAIL のまま。** 基準 1〜3 は現行コードで再確認済み（pytest 370 passed = 修正ラウンドの 369 + 採点ハーネスの
テスト 1、凍結アーカイブのハッシュ不変と再採点の完全再現、dev-ext 再採点の完全再現）。

### 乖離の分析（パターンのみ、ケース本文は引用しない）

**clean 誤検出 5 件（不合格の原因）**: すべて同じ型。docker-compose で複数の service が、**パスワードを含まない接続 URL**（例: キャッシュの
URL）を資格情報らしい名前の変数で受け取っている。GrantLock は D-024 の追補（資格情報らしい名前のキーに入った秘密でないリテラルを
「外部の資格情報への参照」とみなす規則。本来は鍵ファイルのパス用に入れたもの）により、これを資格情報として身分化し、2 つの service が
共有している → G5 と判定した。規則の適用範囲が広すぎた**検出側の誤り**で、慣行差ではない。

**diff 不一致 3 件**: 3 件とも、上の誤検出と同じ G5 が「変更されていない状態」の finding として予測ラベルに混入したもの（期待ラベル自体は
3 件とも予測に含まれている）。v2 の作成者に渡した慣行（名前変更 = G7 + G8、置換 = G6 + G7 + G8 等）とは食い違っておらず、
慣行差による不一致は 0 件。

**planted の見落とし 5 項目**:

| パターン | クラス・面 | 原因 |
|---|---|---|
| リテラルの Slack Webhook URL をワークフローのジョブ env に書く | G1・GitHub Actions | 検出器の例外停止（形式プレフィックスとスキーマ上限の不整合）。見落としとして計上 |
| Terraform のリソース内の入れ子マップ（関数の環境変数ブロックなど）にリテラルの API キーを書く | G1・Terraform | リテラル判定がブロック直下の属性値しか見ず、オブジェクト / マップ式の中の値を読まない |
| リモート MCP サーバの **HTTP ヘッダ**で toolsets を指定・拡大（列挙の追加、`all`） | G2・G3・MCP | スコープを env（`*_TOOLSETS`）と CLI 引数からしか読まず、ヘッダの toolsets 指定を読まない |
| Workload Identity 設定済みの workload に、サービスアカウント鍵 JSON を Secret ボリュームでマウントし、鍵ファイルのパスを env で指す | G6・Kubernetes | Secret ボリューム（キー指定なし）を種別不明の資格情報として扱い、鍵ファイルのパスを指す env をリテラル（秘密でない）として無視するため、静的キーと判定しない（G7 は検出） |

見出しクラス（G2・G3）の見落としは MCP ヘッダの toolsets の 1 パターン（各 1 件）だけで、バーは満たした。

### 判定の扱い

v2 は採点結果を見たため、これで**開示済みコーパス**になった。プロンプトの指示どおり検出器の修正には着手していない。D-024 の
適用範囲、MCP ヘッダの toolsets、Terraform の入れ子マップのリテラル、Secret ボリュームの鍵ファイル、Slack Webhook の例外停止の
5 点を DECISIONS（D-047 / D-048）に記録し、Phase 3 の進め方と合わせて判断する。修正後の合否は新しい封印 holdout（v3）が必要。

## 実リポジトリプローブ

shallow clone（リポジトリ外の作業ディレクトリ）→ scan → lock → check。lock をそのリポジトリ自身から作るため、
出るのは状態クラス（G1/G3/G4/G5/G6）だけで、G2/G7/G8 は構造上出ない。

| リポジトリ（commit） | 面別: 検討ファイル / identity のあるファイル / findings | README 等の未読み取り MCP 設定例 | findings | 妥当 | 誤検出 | 保留 |
|---|---|---|---|---|---|---|
| NagaYu/caplock（`22c5748`） | MCP 5/3/7、GHA 1/1/2、compose・K8s・TF 0 | 1 ファイル | 9 | 2 | 7 | 0 |
| modelcontextprotocol/servers（`3638028`） | MCP 1/1/1、GHA 11/11/41、compose・K8s・TF 0 | 11 ファイル | 42 | 42 | 0 | 0 |
| github/github-mcp-server（`99d6d65`） | MCP 2/2/0、GHA 13/13/36、compose・K8s・TF 0 | 12 ファイル | 36 | 12 | 12 | 12 |
| 合計 | | | **87** | **56** | **19** | **12** |

この表はレビュー時点の検出器（D-036 修正後）による。初回実行では 91 件で、うち 4 件は検出器バグによる誤検出だった
（`run:` 内のシェル変数 `npm_packages` を npm トークンと誤認 → G1+G4 の 2 件、`steps.redact_secrets.outcome` を secrets 参照と
誤読 → G5 の 2 件）。どちらも回帰テスト付きで修正（D-036）。

代表例（パスとクラスのみ）:
- 妥当: `.github/workflows/*.yml` の G4（CODEOWNERS 不在。servers で 40 件、caplock で 2 件）、`.github/workflows/sdk-watch.yml` の
  G5（同一 API キーを 2 ジョブで共有）、`.github/workflows/issue-triage.lock.yml` / `pr-triage.lock.yml` の G5（GitHub トークン
  secret を複数ジョブで共有）
- 誤検出: `fixtures/configs/*.json`・`examples/demo-workspace/.vscode/mcp.json` の G4 / G5（テスト用・例示用の設定を実設定として
  扱った）、`*.lock.yml` の OTLP エンドポイント secret の G5（URL であって資格情報ではない。D-009 で secrets.* を一律に資格情報と
  みなしたコスト）
- 保留: `*.lock.yml` の OTLP ヘッダ secret の G5（認証ヘッダを含むか名前から判別できない）

注意: 3 リポジトリとも compose / Kubernetes / Terraform のファイルを含まず、**新面の実地プローブにはなっていない**。
MCP の設定例の大半は README のコードブロックにあり読み取り対象外のため、MCP 面の「findings 0 件」は「問題なし」ではなく
「対象ファイルが少ない」を意味する（上表の検討ファイル数を参照）。

## 作ったもの（ステップごと）

| Step | 内容 | 主なファイル | テスト |
|---|---|---|---|
| 0 | 264 green 確認、`bench/dev-frozen/` 作成（ハッシュ記録・コミット）、`strict_recorded_g3`（既定 false） | `bench/dev-frozen/`, `grantlock/policy.py` | `test_phase2_policy.py` |
| 1 | docker-compose パーサ（environment 両形式、`${VAR:-default}`、env_file、secrets、build.args）、新 component 種別、適用マトリクス | `grantlock/parsers/compose.py`, `schemas.py` | `test_compose_parser.py` |
| 2 | Kubernetes パーサ（Secret 非デコード、RBAC を Binding 経由で SA に解決、IRSA/WI/Azure WI、workload 参照、レガシー SA トークン） | `grantlock/parsers/k8s.py` | `test_k8s_parser.py` |
| 3 | Terraform 構造パーサ（対象リソース限定、heredoc/jsonencode/policy_document、静的キー資源、計算資源の消費、リテラルの分類と破棄） | `grantlock/parsers/terraform.py` | `test_terraform_parser.py` |
| 4 | scan への統合、新面の owner 解決、新面での G1–G8 結合テスト、新規付与 component による G2（D-031） | `grantlock/inventory.py`, `diff.py` | `test_phase2_integration.py` |
| 5 | dev-ext 生成器（lockfile なし形式、実形式ダミー）、lockless 採点、凍結 dev 再採点、ベースライン実測、公開 API `grantlock.diff` の修正（D-032） | `grantbench/ext_templates.py`, `ext_mutations.py`, `lockless.py`, `generator.py` | `test_bench_ext.py`, `test_public_api.py` |
| 6 | 証拠パック `grantlock evidence`（JSON スキーマ、Markdown、lock 履歴要約、IA-5/AC-6/CC6 対応表） | `grantlock/evidence.py`, `check.py`, `cli.py` | `test_evidence.py` |
| 7 | 実リポジトリプローブと全件レビュー、検出器バグ 2 件の修正 | `grantbench/probe.py`, `reports/phase2_probe*.json` | `test_probe_regressions.py` |
| 8 | holdout 採点ツール（実行は NOT RUN） | `grantbench/holdout_score.py` | `test_holdout_score.py` |
| 9 | README 更新、本報告書 | `README.md`, `reports/phase2.md` | — |

## テスト総数と内訳

合計 **344 passed**（Phase 1 の 264 件は無変更で含まれる）。

| ファイル | 件数 | 区分 |
|---|---|---|
| Phase 1 の 14 ファイル | 264 | 無変更 |
| test_compose_parser.py | 14 | Step 1 |
| test_phase2_integration.py | 13 | Step 4 |
| test_terraform_parser.py | 12 | Step 3 |
| test_k8s_parser.py | 11 | Step 2 |
| test_bench_ext.py | 9 | Step 5 |
| test_evidence.py | 8 | Step 6 |
| test_phase2_policy.py | 6 | Step 0 / 5（凍結アーカイブ・再採点・strict フラグ） |
| test_holdout_score.py | 4 | Step 8 |
| test_probe_regressions.py | 2 | Step 7 |
| test_public_api.py | 1 | Step 5（D-032） |

## 逸脱・未実装・DECISIONS.md に記録した点（D-019 以降）

- **D-019** 凍結アーカイブはコミットする（無編集を git 履歴とハッシュの両方で検証可能にする）。
- **D-021** holdout 作成プロンプトの G8 の記録先（「宣言されていたファイル」）と Phase 1 の G8（参照していた消費 component に出す）が
  食い違いうる。Phase 1 の未変更テストを守るため意味論は変えず、holdout で不一致が出れば慣行差として分けて報告する。
- **D-022** プロンプトの component 種別に、宣言種別（`k8s_secret`、`k8s_rbac`、`terraform`）と消費種別（`terraform_workload`）を追加。
  schema_version は 1.0 のまま（列挙値の追加のみ。Phase 1 テストが 1.0 を固定）。Phase 3 で 1.1 化を検討。
- **D-023** 適用マトリクス: compose は G2/G3 対象外（資格情報の権限モデルが無い）。holdout 生成前にコミット。
- **D-025 / D-027 / D-029** Phase 2 の新テストで期待値を修正した 3 件の透明性記録（いずれも既存の確定規則 D-008 / D-006 との
  矛盾、またはテストヘルパの曖昧さ。実装側を直したものは別記）。
- **D-031** 新規付与リソース（RoleBinding、IAM member/attachment）による既存 identity の権限追加も G2。D-013 の拡張。
- **D-032** Phase 1 の潜在バグ: 公開 API `grantlock.diff` がサブモジュール import で上書きされていた。修正。
- **D-035** 証拠パックの lock 差分履歴は、コアが git を実行しないため `--previous-lock` で渡されたときだけ。
- **D-036** プローブで見つかった誤検出 2 種（npm トークン形状、secrets 参照の境界）を修正。
- **D-037** プローブの気づき（検出器は未変更）: CODEOWNERS 不在時の G4 集約、フィクスチャのパス除外、
  資格情報らしくない secret の扱い、同一ワークフロー内共有の集約表示。
- **D-038** holdout 採点ツール（初版時点では NOT RUN）。
- **D-039** holdout 採点の結果と見落としパターン（A〜H）。検出器は修正せず Phase 3 へ引き継ぐ。

未実装（Phase 2 の範囲外として明示）:
- Helm テンプレート / Kustomize のレンダリング（壊れた YAML として警告のみ）、Terraform のモジュール展開・変数評価・
  `count`/`for_each`、AWS 以外の詳細なポリシー文法（GCP/Azure はロール名のみ）、compose の `extends`・複数ファイルのマージ。
- K8s の暗黙 default ServiceAccount は binding を作らない（D-026）。

## Phase 3（公開）への引き継ぎ事項

1. **GATE 2 FAIL への対応（Phase 3 の前提）**: holdout の見落としパターン A〜D を新テスト付きで塞ぐ。特に A（束縛のない
   Role/ClusterRole を「付与の宣言」として inventory に載せる）は G2/G3 の不合格の直接原因。B・D は Terraform の `var.*` 参照と
   provider ブロックの属性の有無を身分として扱うこと、C は宣言側（SA の連合喪失、静的キー Secret の追加）での G6。
   この holdout はもう「見た」コーパスなので、修正後の再評価には**新しい封印 holdout（別作者・別 seed）**が必要。
   同じ holdout で再採点した数字を合格の根拠にしてはならない。
2. **慣行差の明文化**: `.env` と `.env.example` の役割（E）、資格情報名の変更＝新 ID（F）、`*` への拡大は G2 でもある（G）、
   身分の置換は G7 + G8（H）を SPEC に明記し、次の holdout 作成プロンプトにも記載する。
3. **誤検出の削減（D-037）**: CODEOWNERS 不在の G4 を 1 件に集約、`exclude_paths`（fixtures / examples）、資格情報らしくない
   secret 名の扱い、同一ワークフロー内 G5 の集約表示。いずれも新テストを伴って入れる。
4. **新面の実地検証**: 3 プローブ対象は compose / K8s / Terraform を含まなかった。新面を含む公開リポジトリでの誤検出調査が必要。
5. **スキーマ版**: component 種別・format class の列挙追加に合わせて schema_version 1.1 化と互換ポリシー（1.0 の lock を読める）を整理。
6. **公開時の主張**: README の数値は dev / dev-ext（同一作者の合成コーパス）に留め、holdout（GATE 2 FAIL）と実地プローブの結果は報告書を参照させ、新面の検出力を主張しない。
   証拠パックは「示唆的マッピング」であり準拠を主張しない旨を維持する。
