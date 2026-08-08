# opcua-lift — OPC UA Stateful Corpus Replay

関数レベル（`UA_decodeBinary` 等）のファジングで得た **生のサービス要求ボディ**を、
**ライブの OPC UA サーバに対してフルセッションを張り直して**送り込み、応答を観測する
スタンドアロンツールです。AFLNet ツリーから切り出した自己完結版で、**AFLNet の
チェックアウトも `aflnet.o` も不要**、`cc` 一発でビルドできます。

```
HEL ─▶ ACK ─▶ OPN ─▶ CreateSession ─▶ ActivateSession ─▶ MSG(fuzz body) ─▶ response
```

corpus ファイルの中身は、最後の `MSG` の**ボディ部分のバイト列**として使われます。
ハンドシェイク〜セッション確立はツールが自動で行い、動的フィールド（channelId,
tokenId, seqNum, requestId, authToken）は実行時にサーバ応答から取得してパッチします。
これが「ステートフル replay」の本体です。

---

## なぜこの形なのか（切り出しの方針）

元の `opcua-lift.c` は AFLNet の `aflnet.o`（約2900行）にリンクして、関数
`extract_response_codes_opcua` 1個だけを利用し、`alloc-inl.h` 経由で
`ck_alloc/ck_realloc/ck_free` を使っていました。調査の結果、

- 使う AFLNet シンボルは **`extract_response_codes_opcua` ただ1関数**
- その関数が依存する AFLNet 機能は **`ck_*` アロケータのみ**（`u8/u32` 等の型や
  `FATAL`/`ACTF` 等のマクロは未使用）

だったため、以下だけで完全スタンドアロン化しました：

| ファイル | 役割 |
|----------|------|
| `opcua-lift.c`  | ステートフル replay 本体（ハンドシェイク・フレーミング・送受信）。元から `#include` 行と前方宣言コメントのみ変更 |
| `opcua_state.c` | `extract_response_codes_opcua` を `aflnet.c` から**逐語で**移植 |
| `alloc-shim.h`  | `ck_alloc/ck_realloc/ck_free` を libc の `malloc` 系で実装した最小シム（`alloc-inl.h`/`config.h`/`types.h`/`debug.h` を不要化） |
| `Makefile`      | 自己完結ビルド |
| `replay.sh`     | service 名 → NodeId を解決する replay ラッパ |
| `smoke-test.sh` | サーバ起動〜replay の end-to-end 動作確認 |
| `testcases/readrequest_body.raw` | サンプル入力 |

> 互換性メモ: `opcua_state.c` は `aflnet.c`（commit `212b578`、AFLNet OPCUA 拡張）から
> 逐語で移植しています。上流の同関数が変わったら再移植すれば `aflnet-replay` と
> バイト互換を保てます。

---

## ビルド

```sh
make                 # → ./opcua-lift
make SANITIZE=1      # ASan+UBSan 版（ターゲットサーバも ASan ビルドの時に有用）
make clean
```

依存は libc のみ。グラフ系・graphviz 等は不要です。

---

## 使い方

```sh
./opcua-lift <corpus_file> <port> [node_id [host]]
```

| 引数 | 説明 | 既定値 |
|------|------|--------|
| `corpus_file` | 生のサービス要求ボディ（afl++/SymCC の corpus エントリ等） | （必須） |
| `port`        | ターゲット OPC UA サーバの TCP ポート | （必須） |
| `node_id`     | 10進のサービス NodeId（下表） | `631`（ReadRequest） |
| `host`        | サーバのホスト名 / IP | `127.0.0.1` |

サービス NodeId（open62541 v1.3.x のバイナリ要求 TypeId）:

| service | NodeId |
|---------|--------|
| read    | 631 |
| write   | 673 |
| browse  | 527 |
| call    | 712 |

> `call` は **712**（`CallRequest_Encoding_DefaultBinary`）です。713 は
> `CallResponse` の非符号化 NodeId なので要求には使えません（以前 713 と書いていました）。

`replay.sh` を使えば service 名で指定できます:

```sh
./replay.sh <corpus_file> <port> [read|write|browse|call] [host]
# 例: ./replay.sh testcases/readrequest_body.raw 4840 read 127.0.0.1
```

### 出力

`stderr` に以下を出力します（`aflnet-replay` と同じ並び）:

1. AFLNet 形式の **state code 列**（例 `0-0-`）。各 OPC UA 応答メッセージごとに
   1コード。`ERR` メッセージはエラー StatusCode 下位バイト、それ以外は `0`。
2. 続けて、受信した **生の応答バイト列**（`MSGF...`）。

終了コード:

| code | 意味 |
|------|------|
| `0` | セッション確立 → MSG 送信 → 応答受信まで成功 |
| `1` | いずれかのハンドシェイク段でハンドシェイク失敗 / 接続失敗 |
| `2` | 引数エラー |

---

## 動作確認（smoke test）

任意のローカル open62541 サーバ（`opc.tcp://127.0.0.1:<port>` で listen するもの）に対して:

```sh
./smoke-test.sh /path/to/tutorial_server_variable 4840
```

成功すると state code（例 `0-0-`）と生応答が出て `exit=0` になります。
検証済みターゲット例: open62541 v1.3.4 の `examples/tutorial_server_variable`。

---

## 入力フォーマットについての注意

`corpus_file` は **最後の MSG のボディ**としてそのまま送られます。ツールは NodeId と
RequestHeader を自前で付与するので、corpus には RequestHeader より後ろの
サービス固有ボディ（例: ReadRequest なら `RequestHeader` を除いた残り）を入れます。

- 関数レベルファジング（`UA_decodeBinary` 等）で得たボディはそのまま使えます。
- AFLNet パケットレベルの testcase（`HELF...` で始まる完全セッション）は**この入力では
  ありません**。それらは `aflnet-replay` 側で再生してください。
- 任意のバイト列を入れてもツールはフレーミングして送信します（ハンドシェイク自体の
  疎通確認＝smoke test にはこれで十分。サーバは不正ボディに `Bad_*` を返すだけ）。

---

## ベースライン・ハンドシェイクのバイト列について

`opcua-lift.c` 冒頭の `BASE_HEL` / `BASE_OPN` / `BASE_CREATESESSION` は、実在の
open62541 v1.3.4 セッション（`localhost:4840`、SecurityPolicy=None、匿名ログイン）から
採取した実バイトです。動的フィールドは実行時にパッチされます。別ホスト/ポートでも
endpointUrl 文字列（`opc.tcp://localhost:4840`）はそのまま送られますが、open62541 は
通常これを厳密検証しないため接続は成立します。厳密な endpoint 検証を行うサーバが
相手の場合は、これらのバイト列内の URL を調整してください。
