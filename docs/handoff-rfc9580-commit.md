# RFC 9580 対応変更のコミット手順（ハンドオフ）

このリポジトリの作業ツリーには、draft-05/06 相当の実装を RFC 9580
(<https://www.rfc-editor.org/rfc/rfc9580>) に準拠させる変更が
**未コミット**で残っている。この資料は、それをコミットするための
完全な手順である。後継セッションは手順を上から順に実行するだけでよい。

作業ブランチ・メッセージ・ファイル範囲はすべて決定済みで、
中間コミットのビルド/テストも実測済み（下記「事前検証の証跡」）。

## 前提（ハンドオフ時点の状態、すべて確認済み）

- ブランチ: `main`（origin/main より 1 コミット先行、`c828c1d Add AGENTS.md`）。
  **push は依頼されていないので行わないこと。**
- 作業ツリー全体（変更すべて適用済みの状態）はグリーン検証済み:
  `detekt`（0 finding）→ `assemble` → `test`（166 tests, 0 failed）。
- gpg（gnupg 2.5.24）と gpg-sq（Sequoia Chameleon）は Homebrew で
  インストール済み。フィクスチャ再生成や相互運用確認に使える。
- ローカル確認環境: JDK 17（Temurin）/ Gradle 8.5 wrapper / CI は JDK 21。

## 実行前の準備

インデックスに以前のセッションが部分的に stage した状態が残っているため、
まずまっさらにする（ファイルは消えない）:

```sh
cd /Users/nya2/Developments/openpgp
git reset
git status --short   # 下記「ファイル一覧」と一致することを確認
```

## コミット構成（4 コミット、この順で）

各コミット後に必ず CI と同じ順序の検証コマンドを実行すること
（右のコメントが期待値）:

```sh
./gradlew detekt && ./gradlew assemble && ./gradlew test
# Commit 1 後: 139 tests, 0 failed（実測）
# Commit 2 後: 139 tests, 0 failed（実測）
# Commit 3 後: 166 tests, 0 failed（実測）
# Commit 4 後: 166 tests, 0 failed（コード無変更）
```

依存関係上、commit 1〜3 はこの順序でなければならない
（signature-ext の新コードは packet の V6 クラスを参照するため）。
分割の根拠: commit 1（common の足場）→ 2（PgpData は他と独立した
armor/クリアテキスト系の変更）→ 3（残りすべて。V5→V6 の移行は
parser・decoder・signature-ext が相互依存のため分割不能）。

---

### Commit 1 — common の足場

```sh
git add common
git commit -m "Add RFC 9580 version 6 key fingerprint and algorithm metadata"
```

**ファイル一覧（変更 6、これで common 配下すべて）:**

```
common/src/main/java/dev/keiji/openpgp/FingerprintUtils.kt
common/src/main/java/dev/keiji/openpgp/HashAlgorithm.kt
common/src/main/java/dev/keiji/openpgp/SymmetricKeyAlgorithm.kt
common/src/test/java/dev/keiji/openpgp/FingerprintUtilsEcTest.kt
common/src/test/java/dev/keiji/openpgp/FingerprintUtilsEd25519Test.kt
common/src/test/java/dev/keiji/openpgp/FingerprintUtilsRsaTest.kt
```

内容: `calcV6Fingerprint`（SHA-256 over `0x9B ‖ 4-octet length ‖ key body`）、
`calcV6KeyId`（指紋の上位 64bit）、native 形式
（Ed25519/Ed448/X25519/X448）用 `AlgorithmSpecificField` 追加。
非標準の draft-05 `calcV5Fingerprint`（0x9A）は削除。
`HashAlgorithm` に v6 salt サイズ（Table 23）を追加（ORIGINAL リストの
SHA2_256 重複登録という潜在バグも修正）。`SymmetricKeyAlgorithm` に
CFB IV 算出用の `blockLength` を追加。テストは draft 時代の v5 期待値を
RFC 9580 Appendix A ベクタに置換。

---

### Commit 2 — armor / クリアテキスト框架

```sh
git add packet/src/main/java/dev/keiji/openpgp/PgpData.kt \
        packet/src/test/java/dev/keiji/openpgp/PgpDataTest.kt
git commit -m "Stop emitting the CRC24 footer and reverse dash-escaping (RFC 9580)"
```

**ファイル一覧（変更 2）:**

```
packet/src/main/java/dev/keiji/openpgp/PgpData.kt
packet/src/test/java/dev/keiji/openpgp/PgpDataTest.kt
```

内容: armor 生成時の CRC24 フッター停止（RFC 9580 §6.1。受信側は従来
どおり行があれば無視・検証しない）、クリアテキストの dash-escape 解除
（§7.2）。この 2 ファイルは他の変更と独立しているため単独で切り出せる。

---

### Commit 3 — packet/signature-ext 本体（最大のコミット）

```sh
git add -A packet tools signature-ext
git commit -m "Migrate packet layer to RFC 9580 (v6 packets, PKESK, native ECC)"
```

`git add -A` は Modification / 追加 / 削除 / リネーム（V5→V6）を全部掴む。
この時点で `git status --short` は AGENTS.md と docs/ の 2 件以外空になる
（Commit 4 で処理）。

**ファイル一覧（変更・削除・リネーム・新規の全体。`git status --short`
と突き合わせて使う）:**

```
# --- packet main: 変更 23 ---
packet/build.gradle.kts
packet/src/main/java/dev/keiji/openpgp/packet/Packet.kt
packet/src/main/java/dev/keiji/openpgp/packet/PacketDecoder.kt
packet/src/main/java/dev/keiji/openpgp/packet/PacketEncoder.kt
packet/src/main/java/dev/keiji/openpgp/packet/PacketLiteralData.kt
packet/src/main/java/dev/keiji/openpgp/packet/onepass_signature/PacketOnePassSignatureParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PacketPublicKeyParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PacketPublicKeyV4.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PacketPublicSubkeyParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/PacketSecretKeyParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/PacketSecretKeyV4.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/PacketSecretSubkeyParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/s2k/String2KeyGNUDummyS2K.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/s2k/String2KeySaltedIterated.kt
packet/src/main/java/dev/keiji/openpgp/packet/seipd/PacketSymEncryptedAndIntegrityProtectedDataV2.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/PacketSignatureParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/PacketSignatureV4.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/SignatureParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/subpacket/NotationData.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/subpacket/PreferredAeadCiphersuites.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/subpacket/Subpacket.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/subpacket/SubpacketDecoder.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/subpacket/SubpacketHeader.kt
packet/src/main/java/dev/keiji/openpgp/packet/skesk/PacketSymmetricKeyEncryptedSessionKeyParser.kt

# --- packet main: 削除 4（非標準 v5 クラス） ---
packet/src/main/java/dev/keiji/openpgp/packet/onepass_signature/PacketOnePassSignatureV5.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/PacketSecretKeyV5.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/PacketSecretSubkeyV5.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/PacketSignatureV5.kt

# --- packet main: リネーム 3（V5 -> V6 に内容改変） ---
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PacketPublicKeyV5.kt -> PacketPublicKeyV6.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PacketPublicSubkeyV5.kt -> PacketPublicSubkeyV6.kt
packet/src/main/java/dev/keiji/openpgp/packet/skesk/PacketSymmetricKeyEncryptedSessionKeyV5.kt -> ...V6.kt

# --- packet main: 新規 17 ---
packet/src/main/java/dev/keiji/openpgp/packet/onepass_signature/PacketOnePassSignatureV6.kt
packet/src/main/java/dev/keiji/openpgp/packet/pkesk/package-info.md
packet/src/main/java/dev/keiji/openpgp/packet/pkesk/PacketPublicKeyEncryptedSessionKey.kt
packet/src/main/java/dev/keiji/openpgp/packet/pkesk/PacketPublicKeyEncryptedSessionKeyV3.kt
packet/src/main/java/dev/keiji/openpgp/packet/pkesk/PacketPublicKeyEncryptedSessionKeyV6.kt
packet/src/main/java/dev/keiji/openpgp/packet/pkesk/PacketPublicKeyEncryptedSessionKeyParser.kt
packet/src/main/java/dev/keiji/openpgp/packet/pkesk/EncryptedSessionKey.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PacketPublicKeyFingerprintExtensions.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PublicKeyEd25519.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PublicKeyEd448.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PublicKeyX25519.kt
packet/src/main/java/dev/keiji/openpgp/packet/publickey/PublicKeyX448.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/PacketSecretKeyV6.kt
packet/src/main/java/dev/keiji/openpgp/packet/secretkey/PacketSecretSubkeyV6.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/PacketSignatureV6.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/SignatureEd25519.kt
packet/src/main/java/dev/keiji/openpgp/packet/signature/SignatureEd448.kt

# --- signature-ext main: 変更 3 + 新規 2 ---
signature-ext/src/main/java/dev/keiji/openpgp/packet/Utils.kt
signature-ext/src/main/java/dev/keiji/openpgp/packet/signature/PacketSignatureExtensions.kt
signature-ext/src/main/java/dev/keiji/openpgp/packet/signature/SignatureExtensions.kt
signature-ext/src/main/java/dev/keiji/openpgp/packet/signature/SignatureEd25519Extensions.kt
signature-ext/src/main/java/dev/keiji/openpgp/packet/signature/SignatureEd448Extensions.kt

# --- テスト: 変更 2 ---
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderSecretKeyV4Test.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketAeadEncryptedTest.kt

# --- テスト: 削除 3（draft 時代 v5 ベクタのテスト） ---
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderCertificateV5Test.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderSecretKeyV5Test.kt
packet/src/test/java/dev/keiji/openpgp/packet/onepass_signature/PacketOnePassSignatureV5Test.kt

# --- テスト: 新規 8 ---
packet/src/test/java/dev/keiji/openpgp/packet/Rfc9580TestVectors.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderCertificateV6Test.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderSecretKeyV6Test.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderInlineSignedV6Test.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderPkeskTest.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderArgon2SkeskTest.kt
packet/src/test/java/dev/keiji/openpgp/packet/PacketDecoderGpgFixtureTest.kt
packet/src/test/java/dev/keiji/openpgp/packet/onepass_signature/PacketOnePassSignatureV6Test.kt

# --- テスト: 新規 1（signature-ext） ---
signature-ext/src/test/java/dev/keiji/openpgp/packet/SignatureV6VerifyTest.kt

# --- テストリソース: gpg フィクスチャ 29 + rfc9580 3 ---
# packet/src/test/resources/gpg/ 内訳（Key ID は生成のたびに変わる）:
#   *_rsa3072_publickey.gpg / _armored.gpg / _secretkey.gpg  … 3
#   *_rsa4096_publickey.gpg / _armored.gpg / _secretkey.gpg  … 3
#   *_ed25519_(publickey|publickey_armored|secretkey).gpg    … 3
#       （ed25519 主鍵 + cv25519 ECDH 暗号化サブキー）
#   *_ecdsa_p256_(publickey|publickey_armored|secretkey).gpg … 3
#   *_ecdsa_bp256_(publickey|publickey_armored|secretkey).gpg … 3
#       （Brainpool P-256r1 ECDSA + ECDH）
#   *_hello_txt_signed.gpg … 4 / *_hello_txt_detached.sig … 4 /
#   *_hello_txt_encrypted.gpg … 4
#   hello_txt_clearsigned_by_*.gpg … 1（ed25519 鍵）
#   hello_txt_symmetric_encrypted.gpg … 1（v4 SKESK + v1 SEIPD）
# ※ rsa4096 にはメッセージフィクスチャは無い
# 計 29 ファイル。`ls packet/src/test/resources/gpg | wc -l` で確認。
signature-ext/src/test/resources/rfc9580/A3_ed25519_x25519_certificate_v6.gpg
signature-ext/src/test/resources/rfc9580/A6_cleartext_signed_message_v6.gpg
signature-ext/src/test/resources/rfc9580/A7_inline_signed_message_v6.gpg

# --- ツール ---
tools/gpg-generate-fixtures.sh
```

ファイル数を `ls packet/src/test/resources/gpg | wc -l`（= 29）等で確認可能。

コミットメッセージには下記ボディを付けること:

```
Version renumbering (draft-05/06 "v5" -> RFC 9580 "v6"), removing the
never-standardized v5 packet classes:

- Signature v6: variable-length salt (size octet + Table 23 salt size),
  4-octet subpacket length fields, 4-octet trailer count, key hashing
  with 0x9B + 4-octet length for v6 keys (0x99 + 2-octet for v4 keys),
  salt fed into the hash context first.
- Secret Key v6: S2K parameter count only when encrypted, S2K specifier
  size count for usage 253/254, no 2-octet checksum for cleartext,
  usage 255 rejected on write.
- One-Pass Signature v6: variable-length salt, fixed 32-octet
  fingerprint (key version octet dropped). SKESK v6: version octet 6.
- New pkesk package (Tag 1, previously unsupported): v3 (Key ID) and
  v6 (1-octet size + key version + fingerprint) with algorithm-specific
  encrypted session keys for RSA, ElGamal, ECDH, X25519, X448.
- Native key/signature formats for Ed25519 (27), Ed448 (28), X25519
  (25), X448 (26) as raw fixed-length octets.
- PacketPublicKeyFingerprintExtensions: fingerprint()/keyId() from a
  decoded key packet.
- Decoder/encoder fidelity: remember the decoded packet header format
  and tag (reserved Type ID 20 routes to the SEIPD parser as emitted by
  gpg 2.5 AEAD messages); format-preserving PacketEncoder.encode.
- Fixes found by round-tripping gpg output: subpacket critical bit
  (0x80) and 2-octet length encoding preserved on re-encode;
  NotationData content re-encoded (was silently dropped);
  PreferredAeadCiphersuites content written (was empty);
  String2KeySaltedIterated wire order (salt before count);
  String2KeyGNUDummyS2K parses the GNU magic / mode / serial number;
  v4 secret key IV sized by cipher block length; literal data file
  name length counted in octets.
- signature-ext: verify() handles v6 signatures and native Ed25519
  (27) / Ed448 (28); JDK MessageDigest names for SHA-224, SHA3-256,
  SHA3-512 added.
- Tests: RFC 9580 Appendix A vectors embedded (Rfc9580TestVectors.kt),
  including byte-exact checks of the A.3.1 hashed data streams; gpg
  fixture matrix (tools/gpg-generate-fixtures.sh + packet/src/test/
  resources/gpg/) asserted decode/re-encode byte-exact, with Key IDs
  derived from fixture file names; obsolete draft-era v5 packets are
  rejected.
```

---

### Commit 4 — ドキュメント

```sh
git add AGENTS.md docs
git commit -m "Document RFC 9580 migration in AGENTS.md and docs"
```

- `AGENTS.md`: 参照仕様を draft から RFC 9580 へ、フィクスチャ再生成
  スクリプトと Appendix A ベクタの組み込み位置の言及を追加。
- `docs/handoff-rfc9580-commit.md`: 本資料（来歴として残す。不要なら
  `docs` を add から外して削除してよい）。

---

## 完了確認

```sh
git status --short        # 空であること
git log --oneline -5      # 下記と一致すること
./gradlew detekt && ./gradlew assemble && ./gradlew test   # 最終確認（166 tests, 0 failed）
```

期待される最終ログ（上 = 新しいほう）:

```
<hash> Document RFC 9580 migration in AGENTS.md and docs
<hash> Migrate packet layer to RFC 9580 (v6 packets, PKESK, native ECC)
<hash> Stop emitting the CRC24 footer and reverse dash-escaping (RFC 9580)
<hash> Add RFC 9580 version 6 key fingerprint and algorithm metadata
c828c1d Add AGENTS.md
```

push は未依頼（必要ならユーザーに確認）。

## やってはいけないこと・注意

- `tools/gpg-generate-fixtures.sh` を**実行しない**（鍵が新規生成され
  フィクスチャの Key ID が変わる。テストはファイル名パターンで鍵を特定
  するため再生成しても通るが、不要な diff が生じる）。
- detekt はベースラインなし（`maxIssues: 0`）。検証で finding が出たら
  suppression を安易に足さず、まず内容を確認する。
- フィクスチャ（gpg/）は毎回新しい鍵で生成されるため、**ファイル名の
  Key ID が作業ツリーと本資料で違う場合は本資料の名前を当てにしない**
  （テスト自体はパターンベースで壊れない）。

## 事前検証の証跡（2026-10-08 実施）

- Commit 1 相当の状態（HEAD + common 変更のみ）を checkout 再現して
  `detekt + 全モジュール test` → **139 tests, 0 failed**。
- Commit 2 相当の状態（HEAD + common + PgpData 変更）→ **139 tests, 0 failed**。
- Commit 3 後（= ハンドオフ時の全変更適用状態）→ **166 tests, 0 failed**、
  detekt 0 finding。
- つまりどのコミット時点でも CI 順序の検証が成功することが実測済み。

## 既知の限界（将来の作業用メモ）

- gpg 2.5 系が AEAD メッセージで「v3 PKESK + v2 SEIPD」という RFC 9580
  非準拠のペアを送出する実データに合わせ、デコーダは Type ID 20 とこの
  ペアを寛容に解釈する（生成側で強制はしない）。RFC 厳密化の際は
  PacketDecoder の該当コメント参照。
- クリアテキストの dash-escape 解除は行頭 `- ` のみ対応。
  `-` 以外の文字で始まる行への警告表示（RFC §7.2 の SHOULD）は未実装。
- One-Pass Signature v6 の署名検証は signature-ext の verify 経由では
  未整備（OPS と署名パケットの突き合わせは未実装）。
