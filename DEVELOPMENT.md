# 開発ガイド

リポジトリ全体の構成と統合環境の準備は [README.md](README.md)、
実機環境の操作条件は [AGENTS.md](AGENTS.md) を参照。

## ビルド

サポートするビルド環境は `Dockerfile` の Ubuntu 22.04。
リポジトリのルートで実行する。

```bash
docker build --tag s1n2-gateway:dev .
```

このビルドには `.env`、認証鍵、親リポジトリの設定は不要。
`.dockerignore` でローカル設定・生成物・取得済み依存コードを除外し、
Open5GS は Makefile が指定するコミットから取得する。

Dockerfile と同等のビルドツール・開発ライブラリを備えた Ubuntu 環境では、
次の Make ターゲットも利用できる。生成物は `build/` にまとまる。

| コマンド | 動作 |
|---|---|
| `make` | 必要な Open5GS ソースを取得し、`build/s1n2-converter` をビルド |
| `make -j2` | 同じビルドを最大 2 並列で実行 |
| `make clean` | `build/` を削除（取得済みの `open5gs/` は残す） |
| `make print-objs` | 手書き C 実装のオブジェクト一覧を表示 |
| `make print-asn1` | 取得済み ASN.1 ランタイムのビルド対象数を表示 |
| `make tests` | テストソースがある場合にテスト実行ファイルをビルド |
| `make test` | テストをビルドして実行し、失敗時は非ゼロで終了 |

初回の `make` はネットワーク接続が必要。`make fetch-open5gs` を明示的に
実行すると `open5gs/` を削除して取り直すため、このディレクトリで作業しない。
依存コードを取り直した場合は `make clean` の後にビルドする。

各 C ファイルは `build/obj/` 以下のオブジェクトへコンパイルされる。
コンパイラが生成する `.d` ファイルでヘッダー依存を追跡し、変更されたファイルに
依存するオブジェクトを再ビルドする。Makefile の変更時もオブジェクトを再ビルドする。
NGAP は固定した Open5GS の `lib/asn1c/ngap/meson.build` に列挙された C ファイルを使う。
同ディレクトリに残る旧生成ファイルはビルドに含めない。
S1AP / NGAP の生成コードはそれぞれ `build/lib/` の静的ライブラリにまとめる。

## テストと検証結果

`tests/` の C 回帰テストを `make test` でビルド・実行する。
アプリの `main` を除く本体オブジェクトとリンクする。

- `gtpu_direction`: 上下同一 TEID の転送、逆方向・未知 TEID の拒否、Echo 応答先。
- `nas_algorithms`: 暗号化・整合性アルゴリズムが異なる場合の鍵導出と SMC の補助変換。
- `nas_uplink`: S1AP のデコードから NGAP の生成まで、EEA0/EEA2 + EIA2 と不正 MAC 拒否。
- `nas_downlink`: NEA0/NEA2 + NIA2、COUNT の2回の周回、不正 MAC・再送の拒否、失敗時の状態保持。
- `gtpu_extensions`: 連結した拡張ヘッダー、シーケンス番号、長さ不正の拒否。
- `pdu_address`: PDU Session Establishment Accept の IP 抽出と EPS への反映、欠落・切断・セッション不一致。
- `log_levels`: レベルによる出力制御と1行1イベントの書式。
- `log_privacy`: TRACE でも入力鍵、RAND、導出した NAS 鍵、生ペイロードを出力しないこと。

GTP-U テストは loopback の UDP 2152 を使うため、ネットワークを分離した
コンテナ内で実行する。NAS の鍵・識別子はテスト専用の固定値を使う。

```bash
docker build --target build --tag s1n2-gateway:test .
docker run --rm --network none s1n2-gateway:test make test
```

テストソースがない場合は `make tests` / `make test` が明示的に失敗する。

変更の報告には次を区別して記載する。

- ソースレビューを完了したか。
- Docker イメージのビルドを完了したか。
- 単体テストを実行したか、該当するテストがないか。
- 実機統合試験を実施したか。未実施なら明記する。

実機を使わない相互接続試験は [lab/README.md](lab/README.md) を参照。
固定した Open5GS と srsRAN 4G を使い、起動、合成加入者の作成、登録、双方向 ping、
後片付けまで `lab/run.py` で実行する。単体テストと仮想試験の結果は
[lab/RESULTS.md](lab/RESULTS.md) に記載する。

GitHub Actions は Docker ビルドのみを行う。実機試験は自動実行しない。
ビルド成功だけでは、親リポジトリ、コア網、RG-VPN、eNB、UE との互換性は確認できない。

## ソースを変更するとき

専用ブランチで変更し、Pull Request でレビューする。C11 と既存の警告設定を維持する。

- `src/` が手書き実装。`src/app/main.c` と `src/app/event_loop.c` から処理の流れを追える。
- C-Plane は `src/cplane/s1ap_ngap/dispatcher_*.c` と `src/cplane/nas/nas_*_to_*.c` が変換処理への入口。
- モジュール内だけで使うヘッダーは実装の近く、共通の内部ヘッダーは `include/internal/` にある。
- `include/s1ap/` は同梱の生成コード、`open5gs/` は取得した依存コード。一括整形や通常のリファクタリングから除外する。

プロトコル、認証、ネットワーク、加入者データに関わる変更では、方向
（4G → 5G / 5G → 4G）、メッセージ、状態遷移、失敗時の動作を PR に記載する。
親リポジトリとの統合に関わる作業では、親・子の正確なコミット SHA を記録し、
親の submodule 固定値を維持する。

公開の開発説明はこのファイルに追記する。Git 管理外の `docs/` は
ローカル運用メモ用であり、共有ドキュメントの置き場にはしない。

## ログとモジュール構成

手書き実装は `include/s1n2_log.h` の `LOG_ERROR/WARN/INFO/DEBUG/TRACE` を使う。
`S1N2_LOG_LEVEL` は大文字で指定し、未設定・不明な値は INFO とする。
ログは標準エラーへ `[LEVEL] [file.c] message` の形式で出力する。
鍵・加入者識別子・NAS の生バイト列は TRACE でも出力しない。
`s1n2_dump_hex` は互換用の関数名を保つが、タグと長さだけを記録する。

上り NAS の検証・復号は `nas/security/nas_4g_security_unwrap.c`、
逆方向の NAS Transport 変換は `nas_transport/nas_transport_reverse.c` に分離した。
登録と IP 割り当ての調整は `nas/registration/registration_bridge.c` が担当する。

5G Registration Accept は一時保存し、Registration Complete と PDU Session Request を
コアへ送る。PDU Session Establishment Accept の IPv4 アドレスを受け取ってから
EPS Attach Accept を生成し、S1AP Initial Context Setup に載せる。
UE の Attach Complete はこの経路ではローカルに受け取り、5G Registration Complete を二重送信しない。
IP が取得できなければ固定値へ戻さず変換を失敗させる。
現在の仮想試験で確認した経路は、PDU の受諾 NAS が NGAP Initial Context Setup に含まれるもの。

手書き実装とテストは `-Werror=implicit-function-declaration` を指定し、宣言不足をビルド失敗とする。
OpenSSL 3 の旧 AES/CMAC API の非推奨警告と、依存 ASN.1 コードの警告は残っている。
