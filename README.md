# dmarcsum

DMARC集計レポート（RUA）を Python 標準ライブラリだけで集計するスクリプトです。
外部パッケージのインストールは不要です。

`rua=` で毎日届く gzip / ZIP のXMLをディレクトリに放り込んで実行すると、
送信元IPごとのDMARC pass率と、失敗の原因の切り分け材料を出力します。

## 使い方

```
git clone https://github.com/ac5net/dmarcsum.git
cd dmarcsum
python3 dmarcsum.py <レポートを置いたディレクトリ>
```

同梱のテストデータで動作を確認できます。

```
python3 dmarcsum.py testdata
```

## 出力例

```
読み込んだレポート : 4 件
総メッセージ数     : 570
DMARC pass         : 434 (76.1%)
DMARC fail         : 136 (23.9%)
うち sampled_out   : 60 （pct未満で対象外。実際には隔離/拒否されていない）

=== 送信元IP別 ===
  203.0.113.77                301 通  pass 100.0%
  203.0.113.10                128 通  pass 100.0%
  2001:db8::1                  60 通  pass   0.0%
  198.51.100.25                47 通  pass   0.0%
  2001:db8::2                  20 通  pass   0.0%
  192.0.2.200                   9 通  pass   0.0%
  203.0.113.99                  5 通  pass 100.0%

=== 失敗の生の認証結果（auth_results） ===
  dkim:署名なし            127
  spf:none             60
  spf:pass             47
  spf:permerror        20
  dkim:temperror       9
  spf:softfail         9
```

`spf:pass` が失敗の内訳に47通ある点に注目してください。
SPF認証自体は通っているのに、DMARCとしては失敗しています。
アライメント（`header_from` とのドメイン一致）で落ちているケースです。

## 対応していること

- gzip（`.gz`）、ZIP（`.zip`）、素の `.xml` を透過的に読む
- ZIP内に複数XMLがある場合も全件処理する
- XMLの名前空間を剥がしてから処理する（後述）
- `auth_results` 内の複数の `dkim` / `spf` 要素を扱う
- 要素が欠落していても停止しない
- 壊れたXMLはスキップし、末尾にファイル名とエラーを表示する
- `sampled_out` を失敗と分けて数える

## 実装上の注意（実際に踏んだもの）

### 1. 名前空間を剥がさないとレポートを無言で取りこぼす

送信元によって、ルート要素に既定の名前空間が付いています。

```xml
<!-- 名前空間なし（多数派） -->
<feedback>

<!-- 名前空間あり -->
<feedback xmlns="http://dmarc.org/dmarc-xml/0.1">
```

`xml.etree.ElementTree` は名前空間付きの要素を `{名前空間}record` というタグ名として
扱うため、`root.findall('record')` は **0件を返します。例外は出ません。終了コードも0です。**

検証では、名前空間なし2件＋名前空間あり1件を集計したときに次の差が出ました。

```
名前空間を剥がさない版: 総メッセージ数 264
剥がす版              : 総メッセージ数 565
```

**301通、全体の53%が静かに欠落していました。** `strip_ns()` で全要素のタグから
名前空間を剥がしてから処理しています。

### 2. `policy_evaluated/dkim` は省略されることがある

DKIM署名が無いメッセージのレポートで、この要素自体が存在しないことがあります。
`.find(...).text` と書くと `AttributeError` で停止します。
要素の有無を確認する `text()` ヘルパーを通しています。

欠落時のデフォルトは `fail` にしています。`pass` にすると成功を過大評価します。

### 3. `sampled_out` を失敗と混ぜると影響範囲を過大に見積もる

`pct=25` のようにポリシーを段階適用している場合、対象外になったメッセージには
`policy_evaluated/reason/type` に `sampled_out` が入ります。
これらはDMARCとしては失敗ですが、**実際には隔離も拒否もされていません。**
`p=reject` に上げたときに本当に落ちる通数を知りたいなら、分けて数える必要があります。

## policy_evaluated と auth_results は別物

どちらにも `dkim` と `spf` という同じ名前の要素があり、取り違えると原因を誤診します。
RFC 7489 Appendix C の型定義を見ると、別物であることが機械的に確認できます。

| 要素 | 型 | 取り得る値 |
|---|---|---|
| `policy_evaluated/dkim`, `policy_evaluated/spf` | DMARCResultType | `pass` / `fail` の2つ |
| `auth_results/dkim/result` | DKIMResultType | `none` / `pass` / `fail` / `policy` / `neutral` / `temperror` / `permerror` の7つ |
| `auth_results/spf/result` | SPFResultType | `none` / `neutral` / `pass` / `fail` / `softfail` / `temperror` / `permerror` の7つ |

`auth_results` は**生の認証結果**、`policy_evaluated` は**アライメントまで含めた
DMARCとしての評価結果**です。DMARCは「認証が通ったこと」ではなく
「認証が通ったドメインが `header_from` と揃っていること」を要求します。

## テストデータ

`testdata/` に4パターンを同梱しています（値はすべて文書用に予約された
アドレスと `example.jp` を使ったダミーです）。

| ファイル | 検証内容 |
|---|---|
| `sample-no-namespace.xml` | 名前空間なし。pass / SPFアライメント不一致 / temperror を含む |
| `sample-with-namespace.xml` | 名前空間あり。剥がさないと取りこぼす |
| `sample-pct-sampled-out.xml` | `pct=25` で `sampled_out` を含む |
| `sample-missing-element.xml` | `policy_evaluated/dkim` が欠落 |

実際に届くレポートは gzip または ZIP で圧縮されています。
圧縮した状態でも動作するので、そのまま置いてください。

## 制限

- ポリシー適用の判定は `policy_evaluated` の値をそのまま使っています。アライメントの再計算はしていません
- 失効レポート（RUF / Forensic Report）には対応していません
- 出力はテキストのみです。CSVやJSONが必要なら適宜追加してください

## 関連記事

- [DMARC集計レポート（RUA）を自分で集計する｜policy_evaluatedとauth_resultsを取り違えない](https://ac-5.net/security/dmarc-aggregate-report-parse/)
- [SPFのDNSルックアップ10回制限とPermErrorの原因・対処法](https://ac-5.net/security/spf-10-lookup-limit/)

## 参考

RFC 7489 Section 7.2（Aggregate Reports）および Appendix C（XMLスキーマ定義）

## ライセンス

MIT
