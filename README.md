# What is s1n2-gateway

4G eNBを5GCに対して接続するためのプロトコル変換器。

## 検証済ハードウェア

| 項目 | 仕様 |
|---|---|
| **ホストマシン** | Intel NUC7i7BNH |
| **eNB(基地局)** | Baicells Nova430x (sXGP対応 4G基地局) |
| **UE(端末)** | Google Pixel 8a |

> **NOTE**: eNB の詳細設定は [Wiki: eNB Setup Guide](https://github.com/Ytaihei/s1n2-gateway/wiki/eNB-Setup-Guide) を参照。
> eSIM の登録・設定手順は [Wiki: eSIM Setup Guide](https://github.com/Ytaihei/s1n2-gateway/wiki/eSIM-Setup-Guide) を参照。
> Simlessly の操作手順は公式マニュアルも参照: https://docs.simlessly.com/rsp/user-manual/simlessly/simlessly.html

## 前提ソフトウェア

| ソフトウェア | 最低バージョン |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Docker Engine | 24+ |
| Docker Compose | v2 |

ビルドツール・ライブラリのインストールは不要 (Dockerfile 内で自動取得)。

## Quick Start

```
1. リポジトリ配置    → 下記「リポジトリの配置」
2. .env 設定         → 下記「環境変数の設定」
3. 加入者登録        → Open5GS WebUI + auth_keys.yaml（Wiki: eSIM Setup Guide）
4. eNB 設定          → MCC/MNC/TAC・S1接続先を合わせる（Wiki: eNB Setup Guide）
5. 端末 eSIM/APN設定 → Wiki: eSIM Setup Guide
6. ビルド＆起動      → 下記「ビルド・実行」
```

## リポジトリの配置

本リポジトリは [open5gs-compose](https://github.com/Ytaihei/open5gs-compose)（Open5GS 簡易 Docker 環境）のサブディレクトリとして動作する。
`docker-compose.yml` が親ディレクトリの Open5GS 設定ファイル (`../5g/`, `../open5gs/` 等) を参照するため、以下の手順で配置すること。

```bash
# 1. 親リポジトリをクローン
git clone https://github.com/Ytaihei/open5gs-compose.git
cd open5gs-compose

# 2. 本リポジトリを s1n2-gateway/ ディレクトリにクローン
git clone https://github.com/Ytaihei/s1n2-gateway.git
cd s1n2-gateway
```

最終的なディレクトリ構成：

```
open5gs-compose/                  ← 親リポジトリ (Open5GS Docker環境)
├── 5g/                       ← 5G NF設定ファイル (AMF, SMF, UPF, …)
├── open5gs/                  ← Open5GS Dockerfile・スクリプト
└── s1n2-gateway/                  ← 本リポジトリ
    ├── docker-compose.yml
    ├── Dockerfile
    ├── start.sh
    ├── .env                  ← .env.example からコピーして作成
    ├── config/
    │   └── auth_keys.yaml    ← auth_keys.example.yaml からコピーして作成
    └── src/                  ← s1n2-converter ソースコード
```

## Start s1n2-Gateway

### 環境変数の設定

`.env.example` をコピーして `.env` を作成する。

```bash
cp .env.example .env
```

通常はデフォルト値のまま動作する。変更が必要な場合の主要変数：

| 変数 | デフォルト | 説明 |
|---|---|---|
| `MCC` / `MNC` / `TAC` | `001` / `01` / `1` | PLMN・TAC（eNB側の設定と一致させる） |
| `UE_IPV4_INTERNET` | `192.168.100.0/24` | UE に割り当てる IP プール |
| `MAX_NUM_UE` | `1024` | 最大 UE 数 |

### ローカル専用スクリプト

`start.sh` と `scripts/protect_local_configs.sh` はローカル環境専用で運用し、Git 管理対象外とする。
実装・運用メモは `docs/` 配下に保存する。

> **NOTE**: `S1C_BIND_ADDR`, `N2_REMOTE_ADDR` 等のインターフェース設定は `docker-compose.yml` 内で自動設定されるため、`.env` での設定は不要。

### 認証鍵の設定

`config/auth_keys.yaml` に Open5GS WebUI で登録した加入者の Ki ・ OPc を記載する。テンプレートは `config/auth_keys.example.yaml` を参照。

```bash
cp config/auth_keys.example.yaml config/auth_keys.yaml
# config/auth_keys.yaml を編集し、imsi / ki / opc を Open5GS WebUI の値に合わせる
```

> **WARNING**: `auth_keys.yaml` にはマスター鍵 (Ki ・ OPc) が含まれる。Git 管理外 (`.gitignore` に登録済み) であり、**テスト・開発環境限定** で使用すること。

### ビルド・実行

```bash
# ビルド
docker compose build s1n2

# 起動 (ネットワーク設定・eNB接続・コンテナ起動を一括実行)
# ※ start.sh はローカル管理ファイル
./start.sh

# ログ確認
docker compose logs s1n2 -f

# 停止
docker compose down

# リビルド (コード変更後)
docker compose build s1n2 --no-cache && ./start.sh
```

> **NOTE**: `start.sh` は環境変数でカスタマイズ可能。デフォルト値は検証環境 (Intel NUC + Baicells Nova430x) に合わせてある。
> 別環境では以下のように上書きする：
> ```bash
> PHYS_NIC=eth0 ENB_IP=172.24.0.200 ./start.sh
> ```
> 詳細は [Wiki: eNB Setup Guide](https://github.com/Ytaihei/s1n2-gateway/wiki/eNB-Setup-Guide#startsh-の環境変数) を参照。
> スクリプト実装のローカル管理は `docs/` を参照。

## アーキテクチャ

```
eNB ──S1AP/GTP-U──► s1n2-converter ──NGAP/GTP-U──► AMF / UPF
         (4G)            ↕ NAS変換            (5G)
```

C-Plane は S1AP↔NGAP を変換し、NAS PDU 内部の EPS↔5GS も同時に変換する。
U-Plane は GTP-U ヘッダの TEID を書き換えて中継する。

## 詳細ドキュメント

プロジェクト構成・モジュール設計・命名規則などの詳細は [Wiki](https://github.com/Ytaihei/s1n2-gateway/wiki) を参照。

## License

AGPL-3.0 — See [LICENSE](LICENSE) for details.

This project includes code from [Open5GS](https://github.com/open5gs/open5gs) (AGPL-3.0) and [asn1c](https://github.com/vlm/asn1c) (BSD-2-Clause).
