#!/bin/zsh
#
# Generate GnuPG-based test fixtures for the packet module.
#
# Every fixture is checked in under packet/src/test/resources/gpg/.
# Fixtures are generated deterministically in structure (not content):
# key IDs and fingerprints depend on fresh key generation, so the
# file names carry the gpg-reported Key ID as ground truth for tests.
#
# Usage: zsh tools/gpg-generate-fixtures.sh [output-dir]
#

set -eu

OUTPUT_DIR="${1:-packet/src/test/resources/gpg}"
WORK_DIR="$(mktemp -d)"
export GNUPGHOME="$WORK_DIR/keyring"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

GPG_ARGS=(--batch --pinentry-mode loopback --passphrase '')

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fingerprint_of() {
    GNUPGHOME="$GNUPGHOME" gpg --with-colons --list-keys "$1" 2>/dev/null |
        awk -F: '$1 == "fpr" { print $10; exit }'
}

# For a version 4 key, the Key ID is the low-order 64 bits of the fingerprint.
keyid_of() {
    local fingerprint="$1"
    echo "${fingerprint: -16}"
}

export_key_files() {
    local fingerprint="$1" algorithm="$2"
    local keyid
    keyid="$(keyid_of "$fingerprint")"

    GNUPGHOME="$GNUPGHOME" gpg --export "$fingerprint" \
        > "$OUTPUT_DIR/${keyid}_${algorithm}_publickey.gpg"
    GNUPGHOME="$GNUPGHOME" gpg --armor --export "$fingerprint" \
        > "$OUTPUT_DIR/${keyid}_${algorithm}_publickey_armored.gpg"
    GNUPGHOME="$GNUPGHOME" gpg --export-secret-keys "$fingerprint" \
        > "$OUTPUT_DIR/${keyid}_${algorithm}_secretkey.gpg"

    echo "$fingerprint $algorithm -> $keyid"
}

generate_message_fixtures() {
    local fingerprint="$1" algorithm="$2"
    local keyid
    keyid="$(keyid_of "$fingerprint")"

    # Inline-signed (uncompressed).
    GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --yes --local-user "$fingerprint" -z 0 \
        --output "$OUTPUT_DIR/${keyid}_hello_txt_signed.gpg" --sign "$WORK_DIR/hello.txt"

    # Detached signature.
    GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --yes --local-user "$fingerprint" -z 0 \
        --output "$OUTPUT_DIR/${keyid}_hello_txt_detached.sig" \
        --detach-sign "$WORK_DIR/hello.txt"

    # Public-key encrypted. With a modern gpg default, this is
    # v3 PKESK + v2 SEIPD (AEAD). Note: RFC 9580 pairs a v6 PKESK with
    # a v2 SEIPD, but this is what a stock gpg 2.5 emits, and both
    # packets are still decodable independently.
    GNUPGHOME="$GNUPGHOME" gpg --batch --yes -z 0 --recipient "$fingerprint" \
        --output "$OUTPUT_DIR/${keyid}_hello_txt_encrypted.gpg" \
        --encrypt "$WORK_DIR/hello.txt"
}

mkdir -p "$OUTPUT_DIR"

cat > "$WORK_DIR/hello.txt" << 'EOF'
What we need from the grocery store:

- tofu
- vegetables
- noodles
EOF

#
# Key matrix.
#

GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-generate-key \
    "Fixture RSA3072 <fixture-rsa3072@example.com>" rsa3072 sign 0
RSA3072_FPR="$(fingerprint_of 'Fixture RSA3072')"
GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-add-key \
    "$RSA3072_FPR" rsa3072 encr 0

GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-generate-key \
    "Fixture RSA4096 <fixture-rsa4096@example.com>" rsa4096 sign 0
RSA4096_FPR="$(fingerprint_of 'Fixture RSA4096')"
GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-add-key \
    "$RSA4096_FPR" rsa4096 encr 0

GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-generate-key \
    "Fixture Ed25519 <fixture-ed25519@example.com>" default default 0
ED25519_FPR="$(fingerprint_of 'Fixture Ed25519')"

GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-generate-key \
    "Fixture NIST P-256 <fixture-nistp256@example.com>" nistp256 sign 0
NISTP256_FPR="$(fingerprint_of 'Fixture NIST P-256')"
GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-add-key \
    "$NISTP256_FPR" nistp256 encr 0

if GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-generate-key \
    "Fixture Brainpool <fixture-brainpool@example.com>" brainpoolp256r1 sign 0 2>/dev/null; then
    BRAINPOOL_FPR="$(fingerprint_of 'Fixture Brainpool')"
    GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --quick-add-key \
        "$BRAINPOOL_FPR" brainpoolp256r1 encr 0
else
    echo "Note: Brainpool P-256r1 is not available in this gpg build." >&2
    BRAINPOOL_FPR=""
fi

#
# Key exports.
#

export_key_files "$RSA3072_FPR" rsa3072
export_key_files "$RSA4096_FPR" rsa4096
export_key_files "$ED25519_FPR" ed25519
export_key_files "$NISTP256_FPR" ecdsa_p256
if [ -n "$BRAINPOOL_FPR" ]; then
    export_key_files "$BRAINPOOL_FPR" ecdsa_bp256
fi

#
# Message fixtures.
#

generate_message_fixtures "$RSA3072_FPR" rsa3072
generate_message_fixtures "$ED25519_FPR" ed25519
generate_message_fixtures "$NISTP256_FPR" ecdsa_p256
if [ -n "$BRAINPOOL_FPR" ]; then
    generate_message_fixtures "$BRAINPOOL_FPR" ecdsa_bp256
fi

# Cleartext-signed message (armored) by the Ed25519 key.
GNUPGHOME="$GNUPGHOME" gpg "${GPG_ARGS[@]}" --yes --local-user "$ED25519_FPR" -z 0 \
    --output "$OUTPUT_DIR/hello_txt_clearsigned_by_$(keyid_of "$ED25519_FPR").gpg" \
    --clearsign "$WORK_DIR/hello.txt"

# Symmetrically encrypted (v4 SKESK + v1 SEIPD), AES-256, uncompressed.
GNUPGHOME="$GNUPGHOME" gpg --batch --pinentry-mode loopback --passphrase 'fixture-passphrase' \
    --yes -z 0 --cipher-algo AES256 \
    --output "$OUTPUT_DIR/hello_txt_symmetric_encrypted.gpg" \
    --symmetric "$WORK_DIR/hello.txt"

echo "Fixtures generated in $OUTPUT_DIR"
