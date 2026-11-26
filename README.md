# s1n2-gateway

4G eNB を 5G Core に接続するためのプロトコル変換器。
C-Plane は S1AP ↔ NGAP と NAS PDU 内の EPS ↔ 5GS を変換し、
U-Plane は GTP-U ヘッダーの TEID を書き換えて中継する。

```text
eNB ──S1AP/GTP-U──► s1n2-converter ──NGAP/GTP-U──► AMF / UPF
         (4G)            ↕ NAS 変換            (5G)
```

## 開発を始める

単体のビルドには Docker Engine が必要。C のビルドツールとライブラリは
Dockerfile 内で取得する。親リポジトリ、`.env`、認証鍵、実機はビルドには不要。
初回ビルドには Ubuntu パッケージと Open5GS を取得するネットワーク接続が必要。

```bash
git clone https://github.com/Ytaihei/s1n2-gateway.git
cd s1n2-gateway
docker build --tag s1n2-gateway:dev .
```

この手順はイメージのビルドのみを行う。GitHub Actions もビルドのみを検証し、
eNB・UE との接続や通信は検証しない。
開発用の Make ターゲットと検証の範囲は [DEVELOPMENT.md](DEVELOPMENT.md) を参照。

## リポジトリ構成

| パス | 役割 |
|---|---|
| `src/app/` | 起動、設定読み込み、イベントループ |
| `src/context/` | UE コンテキスト管理 |
| `src/cplane/s1ap_ngap/` | S1AP / NGAP のメッセージ振り分けと変換 |
| `src/cplane/nas/` | 登録・認証・セキュリティ・TAU・PDU セッションの NAS 変換 |
| `src/auth_module/` | 認証設定、加入者情報、Milenage、鍵導出 |
| `src/transport/` | SCTP / UDP トランスポート |
| `src/uplane/` | GTP-U トンネル管理と転送 |
| `src/utils/` | 共通ユーティリティ |
| `include/`, `include/internal/` | 共通ヘッダーと内部インターフェース |
| `include/s1ap/` | 同梱された ASN.1 生成コード |
| `config/auth_keys.example.yaml` | 認証設定のテンプレート |
| `lab/` | 合成加入者と仮想eNB・UEによる、明示実行の相互接続試験 |
| `scripts/check-remote-status.sh` | 認可された実機環境の読み取り専用事前確認 |
| `Dockerfile`, `Makefile` | 単体ビルド |
| `docker-compose.yml` | 親リポジトリに依存する統合構成 |

`open5gs/`（ビルド時に取得）と `build/`（生成物）は Git 管理外。
`include/s1ap/` は生成コードのため、手書き実装の整理・一括整形の対象に含めない。

## 統合環境の準備

実行には [open5gs-compose](https://github.com/Ytaihei/open5gs-compose) 由来の
指定された親リポジトリが必要。`docker-compose.yml` は親の `base/Dockerfile`、
`config/5g/`、`webui/`、`log/` を参照するため、このリポジトリ単体では起動できない。

### 互換性と配置

統合運用では、親リポジトリが submodule として固定するコミットを使う。
本リポジトリの `main` と親の最新ブランチの互換性は保証しない。
指定の統合リポジトリを利用する場合は、その URL とブランチに合わせること。

```bash
# 新規取得時: 親が指定する submodule コミットも取得する
git clone --recurse-submodules https://github.com/Ytaihei/open5gs-compose.git
cd open5gs-compose

# 統合作業の前に親・子の状態と正確なコミットを記録する
git status --short --branch
git rev-parse HEAD
git submodule status -- s1n2-gateway
git -C s1n2-gateway status --short --branch
git -C s1n2-gateway rev-parse HEAD
```

既存の運用環境では、先に状態を確認し、親の submodule 固定値を維持する。
親の下で本リポジトリを別途 clone したり、子だけを最新 `main` に更新したりしない。

```text
open5gs-compose/
├── base/Dockerfile
├── config/5g/
├── webui/
├── log/
└── s1n2-gateway/           # 親が固定する submodule
    ├── docker-compose.yml
    ├── .env               # ローカル設定（Git 管理外）
    └── config/auth_keys.yaml  # 認証鍵（Git 管理外）
```

### 設定ファイル

新規環境では `s1n2-gateway/` 内でテンプレートをコピーする。
既存ファイルを上書きしないよう、以下では `-n` を付けている。

```bash
cp -n .env.example .env
cp -n config/auth_keys.example.yaml config/auth_keys.yaml
```

`.env` の主要変数は以下のとおり。テンプレートの値を実機環境と照合する。

| 変数 | テンプレート値 | 説明 |
|---|---|---|
| `MCC` / `MNC` / `TAC` | `001` / `01` / `1` | eNB と一致させる PLMN・TAC |
| `UE_IPV4_INTERNET` | `192.168.100.0/24` | UE の IP プール |
| `MAX_NUM_UE` | `1024` | 最大 UE 数 |

`S1C_BIND_ADDR`、`N2_REMOTE_ADDR` などは `docker-compose.yml` 内で設定する。
`config/auth_keys.yaml` は Open5GS WebUI の加入者設定と一致させる。
この方式はテスト・開発環境限定で使用し、認証鍵や加入者情報を Git やログに含めない。

### 実行・実機検証

フルスタックの実行は、RG-VPN に接続し実基地局を利用できる認可されたリモートホストに限定する。
実行前に [AGENTS.md](AGENTS.md) の運用条件を確認する。
SSH 設定済みの認可された端末から、次の読み取り専用確認を実行できる。

```bash
./scripts/check-remote-status.sh
```

このスクリプトは親・子の Git 状態、submodule 固定値、コンテナ、SCTP 接続数を確認する。
ログや認証鍵は取得しない。SCTP 接続数やコンテナの状態だけでは UE の通信成功を証明できない。

起動・再起動・設定変更・実機試験は、対象サービス、実行コマンド、復旧方法、
期待する検証結果を確認してから行う。開発エージェントが実施する場合は明示的な承認が必要。
実機用の `docker compose up` をローカル開発や CI の検証手順には含めない。
ユーザーが明示的に依頼する独立した仮想試験は [lab/README.md](lab/README.md) を参照。

承認済みの運用作業で使う基本コマンドは以下のとおり。
認可されたホストの `s1n2-gateway/` で、作業内容に合うものを個別に実行する。
`up` と `down` はこの Compose 構成全体に作用する。

```bash
# コンバーターのイメージをビルド
docker compose build s1n2

# スタックを起動（明示的な承認が必要）
docker compose up -d

# コンテナの状態を確認（UE の通信確認とは別）
docker compose ps

# スタックを停止（明示的な承認が必要）
docker compose down
```

### 検証済みハードウェアと前提ソフトウェア

| 項目 | 仕様 |
|---|---|
| ホストマシン | Intel NUC7i7BNH |
| eNB | Baicells Nova430x（sXGP 対応 4G 基地局） |
| UE | Google Pixel 8a |
| OS | Ubuntu 22.04 LTS |
| Docker Engine / Compose | 24+ / v2 |

## ドキュメント案内

- [lab/README.md](lab/README.md): 仮想LTE試験の起動・検証・後片付け。
- [DEVELOPMENT.md](DEVELOPMENT.md): ビルド、検証、ソース変更の進め方。
- [AGENTS.md](AGENTS.md): 開発エージェント向けの作業・運用条件。
- [Wiki](https://github.com/Ytaihei/s1n2-gateway/wiki): 詳細設計、運用、トラブルシュート。
- [eNB Setup Guide](https://github.com/Ytaihei/s1n2-gateway/wiki/eNB-Setup-Guide): 基地局と物理ネットワークの設定。
- [eSIM Setup Guide](https://github.com/Ytaihei/s1n2-gateway/wiki/eSIM-Setup-Guide): eSIM・加入者設定。
- [Simlessly 公式マニュアル](https://docs.simlessly.com/rsp/user-manual/simlessly/simlessly.html): Simlessly の操作。

`start.sh`、`scripts/protect_local_configs.sh`、`docs/` はローカル専用で Git 管理外。
公開の開発手順は README と DEVELOPMENT.md に記載する。

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.

This project includes code from [Open5GS](https://github.com/open5gs/open5gs) (AGPL-3.0) and [asn1c](https://github.com/vlm/asn1c) (BSD-2-Clause).
