# 仮想LTE相互接続試験

srsUE → ZeroMQ → srsENB → gateway → Open5GS 5GCを独立したDocker網で試験する。
Linux、SCTP、`/dev/net/tun`、Docker Compose、Python 3 + PyYAMLが必要。
物理eNB、SDR、VPN、実加入者設定は使わない。CIからは起動しない。

## 再現手順

リポジトリルートから実行する。

```bash
python3 lab/fetch-sources.py
# 初回: 固定バージョンの5GC/RANとゲートウェイをビルドして試験
python3 lab/run.py --build --ciphering NEA0 --ue-subnet 10.45.0.0/24
# イメージがある場合
python3 lab/run.py --ciphering NEA2 --ue-subnet 10.46.0.0/24
```

`--build`を付けない場合は既存イメージを使う。ゲートウェイのソース変更後は
先に`docker build -t s1n2-gateway:dev .`を実行する。
Docker HubやGitHubに接続できない場合はビルドが失敗するため、古いイメージで
最新差分を検証したことにしない。

依存ソースは`sources.lock.json`のコミットを固定して取得する。
既存チェックアウトのSHA不一致・追跡ファイルの変更はエラーにする。
実行イメージはOpen5GS v2.7.2、srsRAN 4G release_23_11、MongoDB 6.0。

## 実行と後片付け

`run.py`は既存の同名プロジェクトを検出すると開始を拒否する。
過去の`runtime/`を`runtime-history/`へ退避し、新しい合成加入者とランダム鍵を作る。
内部網`10.203.0.0/24`の既存ホスト経路との重複を検査し、5GC起動を待ってから
ゲートウェイ・eNB・UEを起動する。ホストへポートを公開しない。
NET_ADMINとTUNはcoreとueのコンテナのみに与える。

SMFは指定したUEプールから動的にIPを割り当てる。加入者DBに固定IPは設定しない。
ゲートウェイにUEのIPを設定する環境変数も渡さない。
UE/SMF/UPFのIP一致、登録、UEとUPFのTUNを明示した双方向pingを検査する。
成功時も失敗時も`finally`で専用コンテナ・ネットワーク・一時DBボリュームを削除する。

ホストの強制終了などで残った場合のみ、次を実行する。

```bash
docker compose -f lab/compose.yaml down -v
```

`runtime/result.json`が検査結果。生ログ・鍵・設定は`runtime/`に保存する。
`runtime/`、`runtime-history/`、`sources/`はGitと本体Dockerビルドから除外する。
ログ共有時は次のスクリプトを使い、秘密を含む生ファイルを添付しない。

```bash
python3 lab/inspect-logs.py gateway.log ue-console.log --match 'ERROR|WARN|attach' --tail 30
```

ゲートウェイのログレベルは`S1N2_LOG_LEVEL`（既定INFO）。TRACEでも鍵や
加入者識別子・NASの生データは出力しない。コア/RANのログには試験用識別子が残る。

## 範囲

単一UE、IPv4、NIA2 + NEA0/NEA2を対象とする。
実機互換性、複数UE、IPv6専用セッション、ハンドオーバー、TAU、長時間負荷の保証ではない。
実機運用の条件は[AGENTS.md](../AGENTS.md)を参照。

検証済みの構成と結果は [RESULTS.md](RESULTS.md) を参照。
