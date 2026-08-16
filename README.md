# opcua-lift — OPC UA Stateful Corpus Replay

> **In English.** `opcua-lift` takes a *raw OPC UA service-request body* — the
> kind produced by function-level fuzzing of `UA_decodeBinary` with AFL++ or
> SymCC — and executes it against a **live, unmodified** OPC UA server by
> re-establishing a full session first. It performs the
> `HEL → ACK → OPN → CreateSession → ActivateSession` handshake, extracts the
> session-dependent fields (channelId, tokenId, seqNum, requestId, authToken)
> from the server's own responses, patches them into the request, and sends it.
> That is the *Stateful Replay* mechanism of the ICSENG 2026 paper below.
> It is self-contained: no AFLNet checkout, no `aflnet.o`, builds with `cc`.
> `--multi` drives a sequence of service requests over one session.
> **The body of this README is in Japanese**; the source comments, `--help`
> output, and the [Scope and limitations](#scope-and-limitations) section below
> are in English.

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

`--multi` を使うと、1 セッションで**複数のサービス要求を順に流し**、要求と応答を対にして
取り出せます（[複数サービスモード](#複数サービスモード--multi)）。

```
HEL ─▶ ACK ─▶ OPN ─▶ CreateSession ─▶ ActivateSession ─▶ [サービス列] ─▶ CloseSession
```

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
| `smoke-test.sh` | サーバ起動〜replay の end-to-end 動作確認（単一・`--multi` の両方）|
| `multi.py`      | `--multi` スクリプトの生成と、返ってきた framed 応答の読み取り（任意。ビルドには不要）|
| `testcases/`    | サンプル入力（[サンプル](#サンプル)）|

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

モードは 2 つあります。単一サービス（従来）と、1 セッションで要求列を流す `--multi` です。

```sh
./opcua-lift <corpus_file> <port> [node_id [host]]      # 単一サービス
./opcua-lift --multi <script_file> <port> [host]        # 複数サービス
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

### 複数サービスモード（`--multi`）

アプリケーション層のある対象では、**1 セッション 1 MSG では届かない状態**があります。
興味のある状態は列でしか作れないからです（SetPoint を書いてから読み戻す、メソッドを
呼んでから状態機械を観測する、など）。要求 1 件につき状態が 1 歩進む対象なら、N 歩先の
状態は単一サービスモードでは原理的に到達できません。

`--multi` では、スクリプト内の全要求を **1 つのセッション**で順に送り、**要求と応答を
対にして**返します。

```text
script : u32 node_id ; u32 body_len ; u8 body[body_len]                の繰り返し
stdout : u32 magic("LIFT"=0x5446494c) ; u32 node_id ; u32 resp_len ; u8 resp[]  の繰り返し
```

- 整数はすべてリトルエンディアン。`body` は単一サービスモードと同じ
  **RequestHeader を除いたサービス固有ボディ**です。
- `resp_len == 0` は「そのサービスに応答が返らなかった」という**情報**であり、失敗では
  ありません。列はそこで打ち切らず、後続の要求を送り続けます。
- `seqNum` / `requestId` はセッション全体で単調増加します。末尾の `CloseSession` も
  その続きを使います（固定値のままだと巻き戻ってサーバに拒否されます）。
- 応答が `MSGC` で分割されて届いた場合は `MSGF` まで読んで 1 応答にまとめます。

単一サービスモードの出力契約は変わりません（生の応答バイト列をそのまま stdout に出す）。
既存の呼び出し側は影響を受けません。

#### 注意: 単一サービスモードは「動いているように見えて」何も測れていないことがある

**これは失敗として現れません。**応答は返り、state code も出て、exit 0 になります。
気づかないまま測り続けられてしまうので、先に書いておきます。

アプリケーション層を持つ SUT（OPC Foundation の Boiler コンパニオンモデルに沿った
アドレス空間の上に、制御ループ・値域検査・状態機械・インタロックを載せたもの。
本リポジトリには含みません）を C 実装で用意し、gcov で実測した結果です。

| 駆動方法 | Lines | Taken at least once |
|---|---|---|
| 生バイト再送 | 64.84% | 7.92% |
| opcua-lift 単一サービス | 64.84% | 7.92% |
| opcua-lift `--multi` | 93.41% | 63.37% |
| 実クライアント（上限） | 94.51% | 70.30% |

**単一サービスモードが生バイト再送と同じ数字**である点が要点です。この 64.84% は
起動時のアドレス空間構築だけで、制御ループは一度も回っていません。原因は 2 つ:

1. **きれいに閉じたセッションの「最後の MSG」は `CloseSession` です。**
   捕捉セッションから末尾 1 件を取り出す作り方をしていると、replay しているのは
   1 バイトの `CloseSession` になります。手元の seed では boiler 系 7 本すべて、
   汎用 opcua 系 4 本中 2 本がこれに該当していました。
2. **要求 1 件につき状態が 1 歩しか進みません。** 1 Write = 1 tick の対象では、
   約 25 tick 必要なインタロックのトリップに単一サービスでは原理的に到達できません。

アプリケーション層のある対象を測るなら `--multi` を使ってください。単一サービスモードは
メッセージ復号層（`UA_decodeBinary` 相当）を狙う用途のものです。

#### 注意: session 外の discovery サービスは `--multi` に載せられない

`GetEndpoints`（NodeId 428）などの discovery サービスはセッションの外で処理されるため、
`--multi` のスクリプトには含められません。捕捉セッションから要求列を抽出する際は
抽出対象外になり、その seed では `--multi` が成立しません。仕様どおりの挙動なので、
呼び出し側で単一サービス経路にフォールバックしてください。

#### 応答から次の要求へ値を運ぶ（script v2）

サーバが返す値の中には、**それを発行したセッションの中でしか通用しないもの**があります。
Browse の `continuationPoint` が典型です。一度 Browse して得た値をファイルに保存し、
後で BrowseNext に渡しても `Bad_ContinuationPointInvalid` (0x804A0000) になります。
`--multi` のスクリプトに直接書き込んでも同じで、その値は前のセッションのものだからです。

そのため、**セッションが開いている間に応答から要求へ値を移す**必要があります。
これはこのプロセスにしかできません。script v2 はそのためのものです。

```text
script v2 : "LFTS" ; u32 version(=2) ;
              { u32 node_id ; u32 body_len ; u8 body[] ;
                u32 patch_count ;
                  { u32 src_index ; u32 src_off ; u32 dst_off ; u32 len }* }*  の繰り返し
```

- `src_index` … 何番目の要求の応答から読むか（自分より前に限る）
- `src_off` … その**サービスペイロード内**のオフセット。MSG ヘッダ・応答 TypeId・
  ResponseHeader を通過した後を 0 とするので、サーバごとに長さが変わる
  ResponseHeader をスクリプト側が知る必要はありません
- `dst_off` / `len` … この要求のボディのどこへ何バイト書くか

ヘッダのない従来のスクリプトは v1 として今までどおり動きます。patch_count を
足して書き直す必要はありません。

適用できない patch（存在しない応答を参照する、ボディの外に書く、応答が返らなかった）は
**その場で失敗させます**。読み飛ばして送っても応答は返ってくるので、
結果らしきものが出てしまい、実際には何も測れていない状態になるからです。

Browse → BrowseNext の例:

```python
# BrowseResponse のペイロード: results数(4) + statusCode(4) + CP長(4) + CP実体
# BrowseNext のボディ:        release(1) + 個数(4) + CP長(4) + CP実体
script  = struct.pack('<4sI', b'LFTS', 2)
script += struct.pack('<II', 527, len(browse_body)) + browse_body + struct.pack('<I', 0)
script += struct.pack('<II', 533, len(bnext_body))  + bnext_body  + struct.pack('<I', 1)
script += struct.pack('<IIII', 0, 12, 9, 16)   # 応答0の12バイト目から16バイトを、9バイト目へ
```

open62541 v1.3.4 で実測した効果:

| | BrowseNext の結果 |
|---|---|
| 単発 replay（有効な CP を作る手段がない） | `0x804A0000` Bad_ContinuationPointInvalid |
| script v2 で値コピー | `0x00000000` Good |

カバレッジで見ると、シーケンス側だけが `ua_services_view.c` の 24 行
（`browseWithContinuation` と継続位置の探索ループ）に到達します。
`continuationPoint` はサーバ側で `session->continuationPoints` に繋がれているため、
単発 replay ではこの経路に**原理的に**到達できません。

### サンプル

`testcases/` に **そのまま動く `--multi` スクリプトが 2 本**入っています。
生成と読み取りは `multi.py`（標準ライブラリのみ。C のビルドには不要）で行います。

| ファイル | 中身 |
|---|---|
| `read_currenttime_body.raw` | `Server_ServerStatus_CurrentTime` (i=2258) の Value を読む Read ボディ |
| `browse_body.raw` | RootFolder (i=84) を `requestedMaxReferencesPerNode = 1` で Browse するボディ。**必ず continuationPoint が返る** |
| `browsenext_body.raw` | BrowseNext ボディ。continuationPoint の場所は 16 バイトの 0 で埋めてある |
| **`multi_read3.script`** | script v1。同じ Read を 1 セッションで 3 回 |
| **`multi_browse_next.script`** | script v2。Browse → BrowseNext で continuationPoint を運ぶ |

```sh
./opcua-lift --multi testcases/multi_read3.script 4840 127.0.0.1 | ./multi.py decode -
```

```text
[0] node=631  len=70    MSGF  serviceResult=0x00000000 Good
[1] node=631  len=70    MSGF  serviceResult=0x00000000 Good
[2] node=631  len=70    MSGF  serviceResult=0x00000000 Good
```

3 要求が 1 セッションで流れ、`seqNum` が巻き戻らずに 3 応答が対で返ることの確認です。

```sh
./opcua-lift --multi testcases/multi_browse_next.script 4840 127.0.0.1 | ./multi.py decode -
```

```text
[0] node=527  len=128   MSGF  serviceResult=0x00000000 Good  results[0]=0x00000000 Good
[1] node=533  len=124   MSGF  serviceResult=0x00000000 Good  results[0]=0x00000000 Good
```

**`results[0]` を見てください。** patch を外して同じ 2 要求を送ると、BrowseNext は
`results[0]=0x804A0000 Bad_ContinuationPointInvalid` になります。
`serviceResult` はどちらも `Good` なので、**サービス単位の結果だけ見ていると
「動いている」ように見えます**。この差が script v2 の効果そのものです。

```sh
# patch なし（対照）: continuationPoint はプレースホルダの 0 のままになる
./multi.py build /tmp/nopatch.script browse:testcases/browse_body.raw \
                                     browsenext:testcases/browsenext_body.raw
```

#### `multi.py`

```sh
# 生成: <service>:<body ファイル>[+<src>,<src_off>,<dst_off>,<len>]...
./multi.py build out.script read:body.raw read:body.raw
./multi.py build out.script browse:testcases/browse_body.raw \
                            'browsenext:testcases/browsenext_body.raw+0,12,9,16'

# 読み取り: 1 要求 1 行。'-' は標準入力
./opcua-lift --multi out.script 4840 > out.bin && ./multi.py decode out.bin
./multi.py decode out.bin --hex 32        # 生バイトも見る
```

patch を 1 つでも付けると script v2 になります。service 名は `replay.sh` と同じ
（`read` / `write` / `browse` / `browsenext` / `call`）で、10 進の NodeId も直接書けます。

`+0,12,9,16` は「**0 番目の応答**のサービスペイロード **12 バイト目**から
**16 バイト**を、この要求のボディの **9 バイト目**へ書く」という意味です。

```text
BrowseResponse のペイロード : results数(4) + statusCode(4) + CP長(4) + CP実体  → CP は 12
BrowseNext のボディ         : release(1)   + 個数(4)      + CP長(4) + CP実体  → CP は 9
```

> **`len` は continuationPoint の長さに依存します。** サンプルの 16 は実測値で、
> open62541 v1.4.6 / v1.3.9・Eclipse Milo 0.6.12・UA-.NETStandard の 4 実装すべてで
> 16 バイトでした。別の実装で合わない場合は、まず Browse だけを流して
> `./multi.py decode out.bin --hex 40` で CP 長（ペイロード 8 バイト目の Int32）を
> 確認してください。

サンプルは上記 4 実装で実行を確認しています。応答長は実装ごとに違い
（同じ Read で open62541 70B、`readrequest_body.raw` では 52B と 133B）、
**応答サイズを決め打ちしないこと**の実例にもなっています。

### 環境変数

ActivateSession の身元確認トークンは実装ごとに受け付ける形が違います。**実装ごとの
作業はこの切り替えだけ**です。

| 変数 | 効果 |
|------|------|
| `OPCUA_LIFT_ANON=1` | userIdentityToken を null ExtensionObject（`00 00 00`）にする |
| `OPCUA_LIFT_ANON_V14=1` | open62541 v1.4.x の匿名 policyId を持つ ExtensionObject を送る |
| `OPCUA_LIFT_TOKEN_HEX=<hex>` | userIdentityToken を生バイトで直接指定する |
| `OPCUA_LIFT_TIMEOUT=<秒>` | recv タイムアウト（既定 5、上限 300） |

トークンの優先順位は `ANON` → `ANON_V14` → `TOKEN_HEX` → 既定（UserName `user1/password`）です。

実測（サンプル corpus を replay して `0-0-` が出る設定）:

| 実装 | 設定 |
|------|------|
| open62541 v1.4.x | `OPCUA_LIFT_ANON_V14=1` |
| open62541 v1.3.x | 既定（username）または `OPCUA_LIFT_ANON=1` |
| Eclipse Milo | `OPCUA_LIFT_ANON=1` |
| UA-.NETStandard | `OPCUA_LIFT_ANON=1` または `OPCUA_LIFT_ANON_V14=1` |

合わないと `ActivateSession failed: bad StatusCode 0x80200000`
（`BadIdentityTokenInvalid`）で止まります。**これを「対象実装が弱い」と読まないこと。**

JVM 実装（Milo）はセッションを連続して張ると HEL の応答が遅れることがあり、既定の 5 秒
では `HEL/ACK failed: no response` に見えます。`OPCUA_LIFT_TIMEOUT` を伸ばしてください。

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
OPCUA_LIFT_ANON=1 ./smoke-test.sh /path/to/server 4840   # 匿名が要るサーバ
```

単一サービスの replay に続けて、`testcases/` のサンプル `--multi` スクリプト 2 本を
流します。成功すると state code（例 `0-0-`）と生応答、続いて 1 要求 1 行の
デコード結果が出て `exit=0` になります（デコードには python3 を使いますが、
無ければその段だけ飛ばします）。

検証済みターゲット例: open62541 v1.3.4 の `examples/tutorial_server_variable`。
`--multi` を含むサンプルは open62541 v1.4.6 / v1.3.9・Eclipse Milo 0.6.12・
UA-.NETStandard でも実行を確認しています。

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

---

## Scope and limitations

These are design boundaries, not open bugs. Read them before filing an issue.

- **SecurityMode `None` only.** The baseline handshake is captured from an
  unencrypted, anonymous session. `Sign` and `SignAndEncrypt` endpoints are not
  supported. This is why the tool cannot be pointed at a hardened production
  server as-is.
- **The handshake prefix is fixed.** `BASE_HEL` / `BASE_OPN` /
  `BASE_CREATESESSION` are literal captured bytes with runtime field patching.
  Consequently the tool **cannot** exercise bugs in certificate validation,
  trust-list handling, or the secure-channel negotiation itself — only the
  service-dispatch layer reached *after* a session exists.
- **`endpointUrl` is hardcoded** as `opc.tcp://localhost:4840`. Servers that
  strictly validate it need that string edited in the baseline bytes
  (see the section above).
- **OPC UA binary transport only.** No HTTPS/WebSocket transport, no PubSub.
- **Not a fuzzer.** It replays inputs someone else generated. Input generation
  (AFLNet / AFL++ / SymCC) lives outside this repository.

### Validated targets

Measured 2026-08-15, single replay and `--multi` with a 3-request script.
Per-implementation work is *only* the identity-token environment variable
(see [環境変数](#環境変数)); no code changes are needed.

| Implementation | Identity token | Single | `--multi` (3 requests) |
|---|---|---|---|
| open62541 v1.4.6 | `OPCUA_LIFT_ANON_V14=1` | OK | 3 records, 52 B response |
| open62541 v1.3.9 | default (username) or `OPCUA_LIFT_ANON=1` | OK | 3 records, 52 B response |
| Eclipse Milo 0.6.12 (JRE 17) | `OPCUA_LIFT_ANON=1` | OK | 3 records |
| UA-.NETStandard 2.0.0-preview-20260718 | `OPCUA_LIFT_ANON=1` or `ANON_V14=1` | OK | 3 records, 133 B response |
| S2OPC | — | not verified (unrelated harness issue) | — |

Testing against more than one stack is not a formality — two defects were
reachable *only* off open62541, because open62541 happens to exercise the
narrow path:

1. **`ResponseHeader` was assumed to be a fixed 24 bytes.** open62541 returns
   the minimal form, so this never surfaces against it. A server that returns
   `serviceDiagnostics` or a non-empty `stringTable` shifts `sessionId` and
   `authToken`, and everything afterwards fails to decode — which *looks like a
   bug in the target*, silently corrupting measurements. Now walked by
   `skip_response_header()` / `skip_diagnostic_info()` and pinned by
   `test_response_header.c` (`make test`).
2. **`authToken` was capped at 32 bytes.** Milo returns a 32-byte random opaque
   (ByteString) NodeId, 39 bytes on the wire — spec-conformant, so a 32-byte cap
   could never work against Milo. `AUTH_TOK_MAX` is now 128.

### Operational notes

- **Against a target with an application layer, single-service mode can measure
  almost nothing while appearing to work** — it returns a response, prints state
  codes, and exits 0. On an application-layer SUT (a Boiler companion-model
  address space with a control loop, range checks, a state machine and an
  interlock; not included here), gcov gave 64.84% lines / 7.92% branches taken
  for both raw byte resend *and* single-service replay, versus 93.41% / 63.37%
  for `--multi` — against 94.51% / 70.30% for a real client. Two causes: the
  last MSG of a cleanly closed captured session is `CloseSession` (a 1-byte
  request), and one request advances the target by one tick, so a state ~25
  ticks deep is unreachable by construction. Use `--multi` for anything above
  the message-decoding layer. Details in
  [単一サービスモードは「動いているように見えて」何も測れていないことがある](#注意-単一サービスモードは動いているように見えて何も測れていないことがある).
- **Discovery services cannot go in a `--multi` script.** `GetEndpoints`
  (NodeId 428) and friends are handled outside the session, so a seed whose
  requests are discovery-only yields no usable `--multi` script; fall back to
  the single-service path.
- **Never replay against a fuzzing-instrumented build of the target.** Under
  `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, open62541 deliberately tampers
  with the authentication token, so `ActivateSession` cannot succeed with *any*
  identity token. Use a clean build as the replay target; keep coverage or
  sanitizer instrumentation, but not fuzzing-mode instrumentation.
- **Do not assume a response size.** The same `ReadRequest` yields 52 bytes from
  open62541 and 133 bytes from UA-.NETStandard. Callers must read the framed
  length, not a constant.
- **JVM targets need a longer timeout.** Milo delays its `HEL` response when
  sessions are opened back to back; at the default 5 s this surfaces as
  `HEL/ACK failed: no response`. Raise `OPCUA_LIFT_TIMEOUT`.
- **`smoke-test.sh` assumes a locally executable server binary** and therefore
  does not cover containerised or JVM targets (Milo, UA-.NETStandard). It is one
  check, not the verification story. Reproduce those with a published Docker
  port:

  ```sh
  make && make test
  OPCUA_LIFT_ANON_V14=1 ./opcua-lift testcases/readrequest_body.raw 14840 631 127.0.0.1
  OPCUA_LIFT_ANON=1     ./opcua-lift testcases/readrequest_body.raw 14843 631 127.0.0.1
  ```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). This package is extracted from
AFLNet; provenance and attribution are recorded in [`NOTICE.md`](NOTICE.md).

## Citation

If you use this tool in academic work, please cite:

```bibtex
@inproceedings{Matsuzaki2026StatefulReplay,
  author    = {Kazutaka Matsuzaki and Shinichi Honiden},
  title     = {Stateful Replay for Combining State-Oriented Fuzzing and
               Symbolic Execution in Industrial Protocol Testing},
  booktitle = {Advances in Systems Engineering: Proceedings of the 52nd
               International Conference on Systems Engineering, ICSEng 2026,
               Las Vegas, Nevada, USA, August 20--21, 2026},
  series    = {Lecture Notes in Networks and Systems},
  publisher = {Springer},
  year      = {2026}
}
```

This work was supported by JSPS KAKENHI Grant Number JP24K07969 and by the
Telecommunications Advancement Foundation (TAF).
