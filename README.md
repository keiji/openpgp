# OpenPGP encoder/decoder for Kotlin

[![CI](https://github.com/keiji/openpgp/actions/workflows/main.yml/badge.svg)](https://github.com/keiji/openpgp/actions/workflows/main.yml)

Implements OpenPGP packet encoding and decoding as defined in
[RFC 9580](https://datatracker.ietf.org/doc/html/rfc9580).

This is a library, not an application. It provides the building blocks for
parsing, inspecting, and generating OpenPGP messages and keys on the JVM:
algorithms, fingerprints, packet model, and signature verification.

## Modules

| Module | Description |
| --- | --- |
| `common` | OpenPGP primitives: hash / symmetric / public-key / AEAD / compression algorithms, fingerprints, MPI and OID utilities, CRC-24, exceptions |
| `packet` | Core packet model. `PacketDecoder` / `PacketEncoder` are the entry points; one subpackage per packet type (public key, secret key, signature, PKESK, SKESK, SEIPD, ...) |
| `signature-ext` | Signature verification layered on `:packet`. Uses BouncyCastle (`bcprov-jdk18on`) for Ed25519 / Ed448 signature verification |
| `sample` | Runnable demo (`Main.kt`) that decodes a `.gpg` file and verifies signatures |

Dependency direction: `common` <- `packet` <- `signature-ext` / `sample`.

### Supported packet versions

| Packet | Versions |
| --- | --- |
| Public Key / Public Subkey, Secret Key | v4, v6 |
| Signature | v4, v6 |
| One-Pass Signature | v3, v6 |
| PKESK / SKESK (session key packets) | v4, v6 |
| Symmetrically Encrypted and Integrity Protected Data | v1, v2 |
| User ID, User Attribute, Compressed Data, Literal Data, Marker, Padding, Trust | — |

## Requirements

- JDK 17+ (CI runs on Temurin JDK 21)
- Gradle 8.5 (via the included wrapper)
- Kotlin 2.3.20, JUnit 5.11 for tests

## Getting started

Always use the wrapper (`./gradlew`). CI runs detekt first, then assemble and
test — keep that order locally too.

```sh
./gradlew detekt                              # lint (zero-tolerance)
./gradlew assemble                            # build all modules
./gradlew test                                # run all tests
./gradlew :packet:test                        # run tests for a single module
```

## Usage

Decode a `.gpg` file into packets:

```kotlin
import dev.keiji.openpgp.packet.PacketDecoder
import java.io.File
import java.io.FileInputStream

val bytes = FileInputStream(File("message.gpg")).use { it.readAllBytes() }
val packetList = PacketDecoder.decode(bytes)

packetList.forEach { println(it) }
```

See `sample/src/main/java/dev/keiji/openpgp/sample/Main.kt` for a complete
example, including signature verification.

## License

```
Copyright 2023-2026 ARIYAMA Keiji

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
