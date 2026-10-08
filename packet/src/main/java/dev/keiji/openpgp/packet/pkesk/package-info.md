# Public Key Encrypted Session Key packet (PKESK, Tag 1)

Tag 1 — Public Key Encrypted Session Key packet.

- Version 3 (`PacketPublicKeyEncryptedSessionKeyV3`) precedes a v1 SEIPD packet,
  identifies the recipient key by an 8-octet Key ID.
- Version 6 (`PacketPublicKeyEncryptedSessionKeyV6`) precedes a v2 SEIPD packet,
  identifies the recipient key by a 1-octet size, the key version, and the fingerprint.

https://www.rfc-editor.org/rfc/rfc9580#section-5.1
