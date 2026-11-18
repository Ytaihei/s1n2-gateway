# 仮想相互接続と回帰テストの検証記録

## 対象

`chore/repository-cleanup` の変更。変更前のゲートウェイ HEAD は
`7fd8ad68ad1525d637565ac56e0a73aaec0d262c`。
ゲートウェイがビルド時に使う Open5GS ASN.1 依存は
`234da30d930a5697f80fe248886ea6cec98ec12d`。

| 仮想試験の構成要素 | バージョン / ソースコミット |
|---|---|
| Open5GS 5GC | v2.7.2 / `43fa4857cce8af6b6ec3c8e3b0cbf99444948f76` |
| srsRAN 4G（srsUE・srsENB、ZeroMQ） | release_23_11 / `eea87b1d893ae58e0b08bc381730c502024ae71f` |
| MongoDB | 6.0 |

親リポジトリの確認時 HEAD は `1314c5c36e209b19fc5e29adadbe20c5af72382a`、
そのゲートウェイ submodule 固定値は `46e433028d73c1324a6f624c547b6013f68e10da`。
この親の固定値は変更していない。

## 2026-11-18 の最終確認

通常のDockerfileを使って実行用・テスト用イメージをビルドし、成功した。
10月に発生したDocker HubのDNS障害は今回の再試行では発生せず、代替ビルドは不要だった。
ネットワークを分離したコンテナで `make -j2 test` を実行し、8本すべて成功した。
さらに、今回の実行イメージで仮想通信試験を再実行した。

| 設定 | 完了時刻（UTC） | 動的に割り当てられたIP | 検査 | UE→UPF ping | UPF→UE ping |
|---|---|---|---|---|---|
| NEA0 / NIA2 | 09:51:23 | 10.45.0.2 | 9/9成功 | 5/5受信 | 5/5受信 |
| NEA2 / NIA2 | 09:51:57 | 10.46.0.2 | 9/9成功 | 5/5受信 | 5/5受信 |

- [NEA0の検査サマリー](results/2026-11-18-nea0.json)
- [NEA2の検査サマリー](results/2026-11-18-nea2.json)
- [単体テスト8本の結果](results/2026-11-18-unit-tests.txt)
- 実行イメージID: `sha256:ed9ae62fb1e29be93d00c6951b1e8dbc7ca97127defa9fa9d77ab1f5f6144071`
- テストイメージID: `sha256:239f3254c014735467c3160d466f8d8f8a104d0a11a8e28424cf84f527fcee41`
- 両イメージのバイナリSHA-256: `d5aa56aa502f3834d6e1ae1501941b2585598afeeb482c847b405f9f845f7a5b`

今回のバイナリは10月の最終試験に用いたバイナリとも一致した。
Python・シェルの構文検査、Compose設定検証、`git diff --check`、
機密ファイルの除外と試験用認証情報のコミット対象への混入検査を実施した。
ゲートウェイの今回の実行ログにも、試験用の鍵・加入者識別子の一致がないことを確認した。

実行したコマンド（リポジトリルート）:

```bash
docker build --tag s1n2-gateway:dev .
docker build --target build --tag s1n2-gateway:test .
docker run --rm --network none --ulimit core=0 -e S1N2_LOG_LEVEL=ERROR s1n2-gateway:test make -j2 test
python3 lab/run.py --ciphering NEA0 --ue-subnet 10.45.0.0/24
python3 lab/run.py --ciphering NEA2 --ue-subnet 10.46.0.0/24
```

## 2026-10-13 の通信試験（前回記録）

SMF の動的割り当てを使用し、加入者DB・ゲートウェイに固定UEアドレスは設定していない。
次の結果は生ログから分離した検査サマリーとして保存している。

| 設定 | 完了時刻（UTC） | UEに割り当てられたIP | 検査 | UE→UPF ping | UPF→UE ping |
|---|---|---|---|---|---|
| NEA0 / NIA2 | 14:35:56 | 10.45.0.2 | 9/9成功 | 5/5受信 | 5/5受信 |
| NEA2 / NIA2 | 14:36:30 | 10.46.0.2 | 9/9成功 | 5/5受信 | 5/5受信 |

- [NEA0の検査サマリー](results/2026-10-13-nea0.json)
- [NEA2の検査サマリー](results/2026-10-13-nea2.json)

検査は S1 Setup、Security Mode Complete 変換、AMF登録完了、UE attach、
UE/SMF/UPFのアドレス一致、TUNを明示した双方向ping。
最終ソースの Dockerfile build ステージと回帰テスト8本は成功した。
最終実行イメージの作成時は Docker Hub のDNS解決が失敗したため、
build ステージのバイナリを既存実行イメージへコピーした。
テスト用・実行用のバイナリ SHA-256 が一致することを確認した。

- バイナリ: `d5aa56aa502f3834d6e1ae1501941b2585598afeeb482c847b405f9f845f7a5b`
- 実行イメージID: `sha256:16a7ab3d2219d94c14ef2a8d27f0dc20fdf747721764aca3b5f68b9425c7d486`
- テストイメージID: `sha256:f9f76a670605ffe350b367f519db0690382c28f8957cef4d51e7492d45ecbf48`

## 回帰テストの範囲

`make test` は8本の実行ファイルを実行する。詳細とコマンドは
[DEVELOPMENT.md](../DEVELOPMENT.md) を参照。

- GTP-Uの受信方向、上下同一TEID、未知TEID拒否、Echoの返送先。
- GTP-Uの連結拡張ヘッダーと不正な長さの拒否。
- NASアルゴリズム5通りの鍵選択とSMC補助変換。
- 4G上りNASのEEA0/EEA2 + EIA2、不正MAC拒否。
- 5G下りNASのNEA0/NEA2 + NIA2、COUNTの2回の周回、再送拒否、失敗時の状態保持。
- コアが割り当てたIPの抽出、EPSへの反映、セッション不一致・切断入力の拒否。
- ログレベル、1行1イベントの書式、TRACEでの鍵・生ペイロード非出力。

## 制約

確認した通信は単一UE・IPv4・NEA0/NEA2 + NIA2。
PDU Session Establishment Accept がNGAP Initial Context Setupに含まれる経路を確認した。
複数UE、IPv6専用セッション、再接続・ハンドオーバー・TAU、長時間負荷、実物eNBとの相互接続は未検証。
OpenSSL 3 の旧AES/CMAC APIの非推奨警告と、依存するASN.1コードの警告は残る。

実機試験・デプロイは実施していない。実加入者設定やVPN設定を変更していない。
試験後は専用コンテナ・ネットワーク・一時DBを削除した。
鍵・識別子・生ログはコミット対象外の `runtime/` と `runtime-history/` に保持し、
公開する証跡は上記の検査サマリーに限定する。
