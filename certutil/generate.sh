#!/bin/bash
# Enable strict execution
#   -e : exit immediately on any error
#   -x : print each executed command, which in my case, is useful for build logs.
set -xe

# Capture the directory where the script is executed.
initdir="$(pwd)"

# paths to configuration files and certificate source templates:
configdir="$initdir/config"
sourcedir="$initdir/source"

# Output directory for all generated certificates and processed files.
installdir="$initdir/srv03rtm.certs"

# Ensure a clean output directory by deleting any previous run.
rm -rf "$installdir"
mkdir -p "$installdir"

# Helper, create a subdirectory inside $installdir if missing.
# Returns the full path to a created/existing directory.
isubdir() {
    local path="$installdir/$1"
    [ -d "$path" ] || mkdir -p "$path" || return $?
    echo "$path"
}

# #Define output certificate paths inside the "tools" directory.
testrootcert="$(isubdir 'tools')/testroot.cer"
testpcacert="$(isubdir 'tools')/testpca.cer"
vbl03cacert="$(isubdir 'tools')/vbl03ca.cer"
drivercert="$(isubdir 'tools')/driver.pfx"

# ------------------------------------------------------------
# Certificate generation block (runs in a subshell)
# ------------------------------------------------------------
(
certdir="$(isubdir '_gencerts')"
cd "$certdir"

# ============================================================
# Generate TEST ROOT CA certificate
# ============================================================

# Create OpenSSL CA database structure for the root CA.
mkdir 'testroot.db.certs'
touch 'testroot.db.index'
echo '4831793303313605' > 'testroot.db.serial'

# Generate a self‑signed root certificate.
openssl req -x509 -md5 -newkey rsa:1536 -nodes \
  -config "$configdir/testroot.conf" \
  -keyout 'testroot.key' \
  -out 'testroot.pem' \
  -days 73000

# Convert PEM → DER for Windows consumption.
openssl x509 -outform der -in 'testroot.pem' -out "$testrootcert"

# ============================================================
# Generate TEST PCA certificate (signed by Test Root)
# ============================================================

mkdir 'testpca.db.certs'
touch 'testpca.db.index'
echo '3921298631018096' > 'testpca.db.serial'

# Generate PCA CSR.
openssl req -new -newkey rsa:1536 -nodes \
  -config "$configdir/testpca.conf" \
  -keyout 'testpca.key' \
  -out 'testpca.csr'

# Sign PCA using the Test Root CA.
openssl ca -batch -config "$configdir/testroot.conf" \
  -in 'testpca.csr' -out 'testpca.pem'

# Convert PCA PEM → DER.
openssl x509 -outform der -in 'testpca.pem' -out "$testpcacert"

# ============================================================
# Generate VBL03 CA certificate (signed by Test PCA)
# ============================================================

mkdir 'vbl03ca.db.certs'
touch 'vbl03ca.db.index'
echo '2208785574689461' > 'vbl03ca.db.serial'

# Generate VBL03 CA CSR.
openssl req -new -newkey rsa:2048 -nodes \
  -config "$configdir/vbl03ca.conf" \
  -keyout 'vbl03ca.key' \
  -out 'vbl03ca.csr'

# Sign VBL03 CA using Test PCA.
openssl ca -batch -config "$configdir/testpca.conf" \
  -in 'vbl03ca.csr' -out 'vbl03ca.pem'

# Convert VBL03 CA PEM → DER.
openssl x509 -outform der -in 'vbl03ca.pem' -out "$vbl03cacert"

# ============================================================
# Generate DRIVER signing certificate (signed by VBL03 CA)
# ============================================================

# Create driver CSR.
openssl req -new -newkey rsa:1024 -nodes \
  -config "$configdir/driver.conf" \
  -keyout 'driver.key' \
  -out 'driver.csr'

# Sign driver certificate using VBL03 CA.
openssl ca -batch -config "$configdir/vbl03ca.conf" \
  -in 'driver.csr' -out 'driver.pem'

# Export driver certificate + chain into a PFX container.
openssl pkcs12 -export -nodes -password pass: \
  -in 'driver.pem' \
  -inkey 'driver.key' \
  -certfile 'testroot.pem' \
  -certfile 'vbl03ca.pem' \
  -out "$drivercert"

# Copy root cert into setup INF merge directory.
cp "$testrootcert" "$(isubdir 'mergedcomponents/setupinfs')/testroot.cer"

# Cleanup temporary cert generation directory.
cd "$installdir"
rm -rf "$certdir"
)

# ------------------------------------------------------------
# Copy source files into the installation directory
# with path reconstruction (dash → slash)
# ------------------------------------------------------------
for f in "$initdir/source/"*; do 
  # Convert filename dashes into directory separators.
  path="$(sed 's,-,/,g' <<< ${f##*/})"
  cp "$f" "$(isubdir "${path%/*}")/${path##*/}"
done

# ------------------------------------------------------------
# Helper functions for certificate hashing and formatting
# ------------------------------------------------------------

# Extract SHA1 fingerprint from .cer or .pfx.
certsha1() {
  local sha1
  if [ "${1##*.}" = 'cer' ]; then
    sha1="$(openssl x509 -inform der -in "$1" -noout -fingerprint -sha1)"
  elif [ "${1##*.}" = 'pfx' ]; then
    sha1="$(openssl pkcs12 -in "$1" -nodes -passin pass: |
      openssl x509 -noout -fingerprint -sha1)"
  else
    return 1
  fi
  [ "$?" = 0 ] || return 1
  sed 's/:/ /g' <<< "${sha1##*=}"
}

# Join four SHA1 bytes into a single spaced string.
join4() {
  local hash="$(printf '%s%s%s%s ' "$@")"
  echo "${hash:0: -1}"
}

# Convert bytes into "0xNN, 0xNN, ..." format.
joinba() {
  local array="$(printf '0x%s, ' "$@")"
  echo "${array:0: -2}"
}

# Extract public key bytes from a DER certificate.
certpk() {
  openssl x509 -inform der -in "$1" -noout -pubkey |
  grep -Fv -- ----- | base64 -d | xxd -p -c 1 | xargs
}

# Compute SHA1 of a public key byte sequence.
pksha1() {
  local hash="$(printf '%s' "$@" | xxd -p -r | sha1sum)"
  hash="$(sed 's/../& /g' <<< "${hash%% *}")"
  echo "${hash:0: -1}"
}

# ------------------------------------------------------------
# Compute hashes for generated certificates
# ------------------------------------------------------------
testrootsha1="$(certsha1 "$testrootcert")"
testpcasha1="$(certsha1 "$testpcacert")"
driversha1="$(certsha1 "$drivercert")"
testrootpk="$(certpk "$testrootcert")"
testrootpksha1="$(pksha1 "$testrootpk")"

# ------------------------------------------------------------
# Patch certificate hashes into Windows source files
# ------------------------------------------------------------

# Replace embedded Test Root public key hash in policy.cpp.
perl -0777 -pe \
  "s/0x8E, 0xFF, [\s\S]*, 0xDC, 0x53/$(joinba $testrootpksha1)/" \
  -i "$installdir/ds/security/cryptoapi/pki/certstor/policy.cpp"

# Replace Test Root SHA1 in multiple components.
sed -e "s/0xA4, 0xCA, .*, 0xC7, 0xAB/$(joinba $testrootsha1)/" \
  -i "$installdir/base/win32/fusion/sxs/strongname.cpp" \
  -i "$installdir/base/ntsetup/syssetup/crypto.c"

# Replace Test Root public key bytes in mincrypt.
perl -0777 -pe \
  "s/(?<=BYTE rgbTestRoot0_PubKeyInfo

\[\]

= \{)[^}]*/\r\n$(joinba $testrootpk)\r\n/" \
  -i "$installdir/ds/security/cryptoapi/mincrypt/lib/vercert.cpp" \
  -i "$installdir/ds/win32/ntcrypto/mincrypt/vercert.cpp"

# Replace Test Root SHA1 in additional components.
sed -e "s/A4CAECFC.*07B0C7AB/$(printf '%s' $testrootsha1)/" \
  -i "$installdir/ds/win32/ntcrypto/mincrypt/vercert.cpp" \
  -i "$installdir/shell/shell32/defview.cpp" \
  -i "$installdir/windows/core/ntuser/kernel/server.c"

# Replace PCA SHA1 in test scripts.
sed -e "s/52871BBC.*06D7A08D/$(join4 $testpcasha1)/" \
  -i "$installdir/tools/checktestpca.cmd"

# Replace Test Root SHA1 in test scripts.
sed -e "s/A4CAECFC.*07B0C7AB/$(join4 $testrootsha1)/" \
  -i "$installdir/tools/checktestroot.cmd"

# Replace driver certificate SHA1 in post‑build crypto script.
sed -e "s/5B8962DC.*2706CDBC/$(printf '%s' $driversha1)/" \
  -i "$installdir/tools/postbuildscripts/crypto.cmd"