# AGENTS.md

Kotlin/JVM library implementing OpenPGP packet encoding/decoding
([RFC 9580](https://www.rfc-editor.org/rfc/rfc9580)).
It is a library, not an app. Gradle 8.5, Kotlin 2.2.21, JUnit 5.
CI runs on Temurin JDK 21 (local build verified on 17).

## Modules

Dependency direction: `common` <- `packet` <- `signature-ext` / `sample`.

- `common/` — OpenPGP primitives: algorithms (hash/symmetric/public-key/AEAD/compression),
  fingerprints, MPI/OID utils, `parseHexString`, exceptions. No packet logic here.
- `packet/` — core packet model. `PacketDecoder` / `PacketEncoder` are the entry points;
  one subpackage per packet type (`publickey`, `secretkey`, `signature`, `seipd`, `skesk`, ...).
- `signature-ext/` — signature verification layered on `:packet`. Only module with a
  BouncyCastle **implementation** dependency (`bcutil-jdk18on`). In `common`,
  `bcpg-jdk18on` is test-only (used to cross-check against BouncyCastle).
- `sample/` — runnable demo (`Main.kt`, takes a `.gpg` file path as arg). Not published,
  but still linted by detekt.

## Commands

Always use the wrapper (`./gradlew`). CI runs detekt first, then assemble + test —
keep that order locally too.

```sh
./gradlew detekt                              # lint (zero-tolerance; run first)
./gradlew assemble                            # build all modules
./gradlew test                                # all tests
./gradlew :packet:test                        # single module
./gradlew :common:test --tests "dev.keiji.openpgp.Crc24Test"  # single test class
```

On detekt failure, the merged XML report lands in `build/reports/detekt/detekt.xml`.

## detekt is the only style gate

- No formatter (ktlint/spotless) is configured. `kotlin.code.style=official` applies.
- Config: `config/detekt/detekt.yml` with `allRules: true` and `maxIssues: 0` — any
  single finding fails the build. There is **no baseline** (`config/detekt/baseline.xml`
  is referenced but does not exist) — fix code or suppress narrowly with `@Suppress`;
  do not create a baseline for new findings.
- Rules that bite most (non-default limits):
  - MaxLineLength 120 — excluded for `**/test/**`; test files with long hex fixtures
    open with `@file:Suppress("MaxLineLength")`.
  - LongMethod 60 / LongParameterList (function 6, constructor 7) / ReturnCount 4 /
    ThrowsCount 8 / TooManyFunctions 11 / NestedBlockDepth 4.
  - MagicNumber: only -1/0/1/2 allowed inline (tests and `.kts` excluded).
  - `TODO:` / `FIXME:` / `STOPSHIP:` comments are forbidden.
  - No wildcard imports (except `java.util.*`).

## Conventions & quirks

- Kotlin sources live under `src/main/java/...` (not `src/main/kotlin`). Put new Kotlin
  files in the `java` source dir.
- Some packet packages carry a `package-info.md` describing that packet type
  (e.g. `packet/.../skesk/`, `seipd/`, `secretkey/s2k/`). Check for one before editing
  a packet package; add one for new packet types.
- Test fixtures are real OpenPGP artifacts (`packet/src/test/resources`,
  `signature-ext/src/test/resources`) named like `<KeyID>_<algorithm>_<kind>.gpg`.
  Hex literals in tests parse via `parseHexString(value, ":")` from `common`.
- `tools/gpg-generate-fixtures.sh` regenerates the gpg-based fixtures in
  `packet/src/test/resources/gpg/` with fresh keys (Key IDs change per run;
  tests locate fixtures by name pattern, not by hard-coded Key ID).
  RFC 9580 Appendix A test vectors are embedded in the Kotlin tests
  (`Rfc9580TestVectors.kt` and per-test constants).
- Publishing (`common`/`packet`/`signature-ext`): maven-publish + GPG signing
  (`useGpgCmd`), output to local `build/repos/{releases,snapshots}` — never a remote
  repo. Version is defined once in root `build.gradle.kts` (`versionCode`).
- Dokka generates API docs but is disabled for `common` and `sample`
  (`exclude_dokka_modules` in root `build.gradle.kts`).
