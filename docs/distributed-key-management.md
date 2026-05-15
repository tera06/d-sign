# 分散署名における「鍵管理の分散化」改善案

## 現状のボトルネック

現在の実装では、`SecretKeyShareRepository` / `PublicKeyRepository` が `Crypter` を使って保存時に暗号化していますが、
暗号鍵は単一の環境変数 `DKMS_MASTER_KEY` から読み出されています。

このため、署名は閾値分散でも、**保管鍵 (at-rest key) が単一障害点**になっています。

- どれか 1 ノードで `DKMS_MASTER_KEY` が漏えいすると、保存済みの全 share を復号できる可能性がある
- 運用上もローテーションや失効がノード単位でできない

## 目標アーキテクチャ

### 1) ノードごとに KEK を分離
- 各ノードが独立した KEK (Key Encryption Key) を持つ
- KEK は Cloud KMS/HSM で管理し、アプリは平文 KEK を保持しない

### 2) DEK 封筒暗号化 (Envelope Encryption)
- `SecretKeyShare` 保存時にランダム DEK を生成
- `share` は DEK で暗号化
- DEK はそのノードの KMS KEK でラップして保存
- 復号時は KMS で DEK をアンラップし、share を復号

### 3) 鍵メタデータの永続化
暗号文と一緒に以下を保存:
- `key_id` (どの KEK でラップしたか)
- `alg` (AES-GCM など)
- `nonce`
- `wrapped_dek`
- `ciphertext`
- `version`

これでノード単位ローテーションと後方互換が可能になります。

## コード修正方針

### A. `Crypter` を KMS 抽象に置き換える
`platform/repository/with_threshold_crypto/key_repository.rs` で `Crypter` 直依存をやめ、次の trait を導入します。

- `KeyManagementService`
  - `wrap_key(plaintext_dek) -> wrapped_dek`
  - `unwrap_key(wrapped_dek, key_id) -> plaintext_dek`
  - `active_key_id() -> key_id`

- `EnvelopeCrypter`
  - `encrypt(plain_bytes) -> EncryptedBlob`
  - `decrypt(blob) -> plain_bytes`

`EncryptedBlob` は上のメタデータを持つ構造体として `bincode` で保存します。

### B. リポジトリの責務分離
- `PublicKeyRepository` は公開鍵なので暗号化不要（改ざん対策は署名/ハッシュで十分）
- `SecretKeyShareRepository` のみ機密保護を実施

### C. キー共有配置の見直し
- 1 ノード = 1 share を基本とし、同一ノードに複数 share を置かない
- 署名時は libp2p 経由で share 署名を収集し、集約ノードは share を保存しない

### D. ローテーション手順
- 新 KEK を KMS で有効化
- 新規保存分は新 KEK を使用
- 旧データはバックグラウンドで再ラップ（decrypt DEK -> re-wrap）
- 完了後に旧 KEK を disable/schedule deletion

## 最小実装ステップ (このリポジトリ向け)

1. `Crypter` を `EnvKms` + `EnvelopeCrypter` に分離
2. `SecretKeyShareRepository` の保存フォーマットを `EncryptedBlob` に変更
3. `key_id` つき復号を実装
4. 既存データ互換のため v1/v2 フォーマット判定を追加
5. `init_keys` 実行時に「同一ノードへ重複 share 保存禁止」チェックを追加

## セキュリティ運用チェックリスト

- `DKMS_MASTER_KEY` のような平文マスター鍵を廃止
- KMS IAM を最小権限化 (wrap/unwrap のみ)
- ノード認証 (mTLS/Noise) と監査ログを必須化
- share 復号・署名要求にレート制限を導入
- インシデント時の KEK revoke / re-wrap 手順を runbook 化

