# STATUS

Phase 1 完了（2026-11-07）。GATE 1 自己判定: PASS（詳細は reports/phase1.md）。Phase 2 には未着手。

| Step | 内容 | 状態 | pytest（そのステップ完了時点） |
|---|---|---|---|
| 0 | 雛形 | done | 1 passed |
| 1 | スキーマと身分モデル | done | 110 passed |
| 2 | MCP パーサ | done | 123 passed |
| 3 | GHA パーサ | done | 143 passed |
| 4 | .env パーサ | done | 150 passed |
| 5 | 身分構築 / owner | done | 178 passed |
| 6 | lock | done | 190 passed |
| 7 | diff / G1–G8 / 重大度 | done | 225 passed |
| 8 | GrantBench 生成器 | done | 241 passed |
| 9 | 採点ハーネス | done | 251 passed |
| 10 | CLI / SARIF / README / 報告書 | done | 264 passed |

dev 採点（reports/phase1_scores.json）: 全クラス recall 10/10、clean 誤検出 0/24、diff_pair 16/16。
ベースライン（追記、実測）: gitleaks 8.30.1 G1 6/10・trufflehog 3.99.8 G1 7/10、G2–G8 は両者 0/10、clean 誤検出 両者 0/24。

# Phase 2

凍結アーカイブ: `bench/dev-frozen/`（Phase 2 Step 0 で `bench/dev/` を変更前にコピー、1788 ファイル）
`corpus_sha256 = 806d821b43fe1813f21d0c7dded45e2b5871b50426a012fd791dbf5627aeae76`（Phase 1 記録値と一致）。
以後編集しない。`tests/test_phase2_policy.py::test_frozen_dev_archive_unchanged` で毎回検証。

| Step | 内容 | 状態 | pytest |
|---|---|---|---|
| 0 | 状態確認・凍結アーカイブ・strict_recorded_g3 | done | 269 passed（Phase 1 の 264 + 5） |
| 1 | docker-compose パーサ | done | 282 passed |
| 2 | Kubernetes パーサ | done | 293 passed |
| 3 | Terraform パーサ | done | 305 passed |
| 4 | モデルと scan の統合（+ D-031） | done | 318 passed |
| 5 | dev-ext 生成器・採点・凍結 dev 再採点・ベースライン | done | 330 passed |
| 6 | 証拠パック | done | 338 passed |
| 7 | 実リポジトリプローブ（+ D-036 修正 2 件） | done | 340 passed |
| 8 | holdout 採点 | 初版時点は NOT RUN → 追記で採点実施: G2 6/7・G3 5/7・G7 8/8・平均 85.7%・clean 0/16（基準 4 不合格） | 344 passed |
| 9 | README / Phase 2 報告書 | done | 344 passed |

Phase 2 完了（2026-11-07）。GATE 2 自己判定: **FAIL（確定）** — holdout の G3 が 71.4%（< 80%）、平均 85.7%（< 90%）。詳細は reports/phase2.md、D-039。Phase 3 には未着手。

# Phase 2 修正ラウンド（D-039 の盲点）

開始コミット `ef3c50b`。開示済み holdout は以後「回帰コーパス」として使う（数字は到達度であり合否ではない。再ゲートは将来の封印 holdout v2）。

| Step | 内容 | 状態 | pytest |
|---|---|---|---|
| 0 | 開始状態の記録（`reports/phase2-fix-start.json`） | done | 344 passed |
| 1 | K8s 束縛のない Role/ClusterRole（D-040） | done | 349 passed |
| 2 | Terraform provider ブロックの資格情報（D-041） | done | 355 passed |
| 3 | K8s 宣言側の G6（D-042） | done | 359 passed |
| 4 | Terraform の var.* 資格情報参照（D-043） | done | 363 passed |
| 5 | .env の意味論（D-044） | done | 367 passed |
| 6 | diff の二重ラベル（D-045、既存の意味論のため実装変更なし） | done | 369 passed |
| 7 | 回帰確認・到達度・報告書（`reports/phase2-fix.md`） | done | 369 passed |

修正ラウンド完了。凍結 dev・dev-ext は開始数字と完全一致。開示済み holdout の到達度: G2 7/7・G3 7/7・G6 8/8・G8 8/8・clean 0/16・diff 4/8（目標 6/8 未達、すべて慣行差）。**GATE 2 の判定は FAIL のまま**（再ゲートは封印 holdout v2）。

開始数字: 凍結 dev 全クラス 10/10・clean 0/24・diff 16/16／dev-ext 全クラス 6/6・clean 0/12・diff 8/8／
開示済み holdout G1 8/8・G2 6/7・G3 5/7・G4 8/8・G5 8/8・G6 3/8・G7 8/8・G8 5/8・clean 0/16・diff 4/8。

# GATE 2 再ゲート（holdout v2）

封印 holdout v2（88 件、seed 60221407、hash 一致）を現行コード（修正ラウンド後、検出器は無変更）で採点。
G2 7/8・G3 7/8・G7 8/8・平均 91.7%（基準内）、**clean 誤検出 5/16 = 31.25%（基準 ≤ 5% を超過）** → **GATE 2: FAIL（最終）**。
参考: G1 6/8（うち 1 件は検出器の例外停止を失敗として計上、D-047）、G4/G5/G7/G8 8/8、G6 7/8、diff 5/8。ベースライン G1 各 5/8。
基準 1〜3 は再確認済み（370 passed、凍結 dev・dev-ext 再採点は完全一致）。v2 は開示済みコーパスになった。詳細は reports/phase2.md。

# 修正ラウンド 2（GATE 2 は FAIL のまま。再検証のみ）

| Fix | 内容 | 状態 | pytest |
|---|---|---|---|
| A | compose の D-024 追補を鍵ファイルのパスに限定（D-049） | done | 374 passed |
| B | Slack Webhook の形式プレフィックスとスキーマの整合（D-050） | done | 377 passed |
| 検証 | 凍結・dev-ext 完全一致、v1 不変、v2 再検証（clean 0/16・G1 7/8・diff 8/8・見出し後退なし）、プローブ不変（`reports/phase2-fix2.md`） | done | 377 passed |

**GATE 2 の正式判定は FAIL（v2 再ゲート、D-048）のまま。** 本ラウンドの数字は開示済みコーパスでの再検証であり合否ではない（D-051）。再判定は封印 holdout v3。
