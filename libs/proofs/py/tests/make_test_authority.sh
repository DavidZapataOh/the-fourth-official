#!/bin/sh
# Writes libs/proofs/vectors/rfc3161.json from a throwaway local timestamp authority.
# Needs OpenSSL 3.4 or later (ts, -not_before/-not_after); set OPENSSL to choose the binary.
set -eu

OPENSSL="${OPENSSL:-openssl}"
OUT="$(cd "$(dirname "$0")/../../vectors" && pwd)/rfc3161.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

DATA="The Fourth Official RFC 3161 test vector"

cat > tsa.cnf <<'EOF'
[ tsa ]
default_tsa = tsa_config

[ tsa_config ]
serial = serial
crypto_device = builtin
default_policy = 1.3.6.1.4.1.99999.1
signer_digest = sha256
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256

[ root_ext ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ tsa_ext ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
echo 01 > serial

root() {
  "$OPENSSL" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$1.key" -out "$1.pem" -subj "/O=Fourth Test/CN=$2" \
    -not_before 20260101000000Z -not_after 20360101000000Z \
    -config tsa.cnf -extensions root_ext 2>/dev/null
}

authority() {
  "$OPENSSL" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$1.key" -out "$1.csr" -subj "/O=Fourth Test/CN=$2" 2>/dev/null
  "$OPENSSL" x509 -req -in "$1.csr" -CA root.pem -CAkey root.key -set_serial "$3" \
    -not_before "$4" -not_after "$5" -extfile tsa.cnf -extensions tsa_ext -out "$1.pem" 2>/dev/null
}

reply() {
  "$OPENSSL" ts -reply -config tsa.cnf -queryfile request.tsq -inkey "$1.key" -signer "$1.pem" \
    -out "$1.tsr" 2>/dev/null
}

root root "Fourth Test Root"
root other "Fourth Untrusted Root"
authority tsa "Fourth Test Timestamp Authority" 2 20260101000000Z 20360101000000Z
authority expired "Fourth Expired Timestamp Authority" 3 20200101000000Z 20210101000000Z

DIGEST="$(printf '%s' "$DATA" | "$OPENSSL" dgst -sha256 -r | cut -d' ' -f1)"
"$OPENSSL" ts -query -digest "$DIGEST" -sha256 -cert -no_nonce -out request.tsq 2>/dev/null
reply tsa
reply expired
"$OPENSSL" ts -reply -in tsa.tsr -token_out -out tsa.tst 2>/dev/null
"$OPENSSL" ts -verify -digest "$DIGEST" -in tsa.tsr -CAfile root.pem >/dev/null
"$OPENSSL" ts -reply -in tsa.tsr -text > tsa.txt 2>/dev/null
SIGNED_AT="$(sed -n 's/^Time stamp: //p' tsa.txt)"
SERIAL="$(sed -n 's/^Serial number: //p' tsa.txt)"

python3 - "$OUT" "$DATA" "$DIGEST" "$SIGNED_AT" "$SERIAL" "$OPENSSL" <<'EOF'
import base64, json, subprocess, sys
from datetime import UTC, datetime
from pathlib import Path

out, data, digest, signed_at, serial, openssl = sys.argv[1:]
read = lambda name: Path(name).read_text()
b64 = lambda name: base64.b64encode(Path(name).read_bytes()).decode()
when = datetime.strptime(signed_at, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
version = subprocess.run([openssl, "version"], capture_output=True, text=True).stdout.strip()
vector = {
    "source": f"libs/proofs/py/tests/make_test_authority.sh ({version})",
    "data": data,
    "data_sha256": digest,
    "root_certificate": read("root.pem"),
    "untrusted_root_certificate": read("other.pem"),
    "authority_certificate": read("tsa.pem"),
    "response": b64("tsa.tsr"),
    "token": b64("tsa.tst"),
    "expired_authority_response": b64("expired.tsr"),
    "expected": {
        "signed_at": when.isoformat(),
        "authority": "CN=Fourth Test Timestamp Authority,O=Fourth Test",
        "serial": int(serial, 16),
    },
}
Path(out).write_text(json.dumps(vector, indent=2) + "\n")
EOF
echo "wrote $OUT"
