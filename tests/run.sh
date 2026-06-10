#!/usr/bin/env bash
# sakura test harness:
#   1. in-binary known-answer tests (SHA-256 + BIP-340 verify/sign + secp units)
#   2. SHA-256 differential vs the system `sha256sum` across length boundaries
#   3. full HTTP end-to-end Blossom flow against a live server
#
# Usage: tests/run.sh [path-to-sakura-binary]   (default: ./sakura)
set -u

BIN="${1:-./sakura}"
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$1"; }
chk()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want=$2 got=$3)"; fi; }

if [ ! -x "$BIN" ]; then echo "no binary at $BIN — build first: odin build . -out:sakura -o:speed"; exit 1; fi

TD=$(mktemp -d "${TMPDIR:-/tmp}/sakura-tests.XXXXXX")
echo "workdir: $TD"

# ----------------------------------------------------------------------------
echo "== 1. in-binary self-test =="
if "$BIN" --selftest > "$TD/selftest.out" 2>&1; then
  ok "--selftest exit 0"
else
  bad "--selftest exit nonzero"; cat "$TD/selftest.out"
fi
# surface the internal counts
tail -n1 "$TD/selftest.out"

# ----------------------------------------------------------------------------
echo "== 2. SHA-256 differential vs sha256sum =="
# Boundary lengths around the 64-byte block + the 55/56 padding edge.
for n in 0 1 2 3 31 32 55 56 57 63 64 65 119 120 127 128 191 192 1000 65536 100000; do
  head -c "$n" /dev/urandom > "$TD/d.bin"
  want=$(sha256sum "$TD/d.bin" | cut -d' ' -f1)
  got=$("$BIN" --sha256 "$TD/d.bin")
  chk "sha256 len=$n" "$want" "$got"
done
# a few random sizes for good measure
for i in 1 2 3 4 5; do
  n=$(( (RANDOM*RANDOM) % 200000 ))
  head -c "$n" /dev/urandom > "$TD/d.bin"
  want=$(sha256sum "$TD/d.bin" | cut -d' ' -f1)
  got=$("$BIN" --sha256 "$TD/d.bin")
  chk "sha256 random len=$n" "$want" "$got"
done

# ----------------------------------------------------------------------------
echo "== 3. HTTP end-to-end =="
SECKEY=$(head -c32 /dev/urandom | xxd -p -c64)
PUBKEY=$("$BIN" --pubkey "$SECKEY")
PORT=$(( 20000 + (RANDOM % 20000) ))
SAKURA_DATA="$TD/data" SAKURA_PORT="$PORT" SAKURA_REQUIRE_AUTH=true "$BIN" > "$TD/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 0.6

B="http://127.0.0.1:$PORT"
printf 'hello blossom from sakura' > "$TD/blob.txt"
HASH=$(sha256sum "$TD/blob.txt" | cut -d' ' -f1)
UPTOK=$("$BIN" --make-token "$SECKEY" upload "$HASH")

# upload (201)
code=$(curl -s -o "$TD/desc.json" -w '%{http_code}' -X PUT --data-binary @"$TD/blob.txt" \
  -H "Authorization: Nostr $UPTOK" -H "Content-Type: text/plain" "$B/upload")
chk "PUT /upload -> 201" 201 "$code"
grep -q "\"sha256\":\"$HASH\"" "$TD/desc.json" && ok "descriptor has sha256" || bad "descriptor sha256"

# re-upload same owner (200)
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$TD/blob.txt" \
  -H "Authorization: Nostr $UPTOK" "$B/upload")
chk "re-upload -> 200" 200 "$code"

# no-auth upload (401)
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$TD/blob.txt" "$B/upload")
chk "no-auth upload -> 401" 401 "$code"

# tampered body vs token x-tag (hash mismatch -> 401, token x no longer matches)
printf 'tampered' > "$TD/bad.txt"
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$TD/bad.txt" \
  -H "Authorization: Nostr $UPTOK" "$B/upload")
chk "wrong-x-tag upload -> 401" 401 "$code"

# GET (200 + exact bytes)
curl -s "$B/$HASH" > "$TD/got.bin"
code=$(curl -s -o /dev/null -w '%{http_code}' "$B/$HASH")
chk "GET blob -> 200" 200 "$code"
gh=$(sha256sum "$TD/got.bin" | cut -d' ' -f1)
chk "GET body hash matches" "$HASH" "$gh"

# HEAD (no body, correct content-length)
cl=$(curl -s -I "$B/$HASH" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-length"{print $2}')
chk "HEAD content-length" 25 "$cl"

# range (206 + partial)
code=$(curl -s -o "$TD/range.bin" -w '%{http_code}' -H "Range: bytes=6-10" "$B/$HASH")
chk "range -> 206" 206 "$code"
chk "range body" "bloss" "$(cat "$TD/range.bin")"

# list (contains the blob)
curl -s "$B/list/$PUBKEY" > "$TD/list.json"
grep -q "$HASH" "$TD/list.json" && ok "list contains blob" || bad "list missing blob"

# expired token (401)
EXP=$("$BIN" --make-token "$SECKEY" upload "$HASH" 1000000000)
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$TD/blob.txt" \
  -H "Authorization: Nostr $EXP" "$B/upload")
chk "expired token -> 401" 401 "$code"

# wrong-verb token (delete token used to upload -> 401)
WV=$("$BIN" --make-token "$SECKEY" delete "$HASH")
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @"$TD/blob.txt" \
  -H "Authorization: Nostr $WV" "$B/upload")
chk "wrong-verb token -> 401" 401 "$code"

# delete (200) then GET (404)
DEL=$("$BIN" --make-token "$SECKEY" delete "$HASH")
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Nostr $DEL" "$B/$HASH")
chk "DELETE -> 200" 200 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$B/$HASH")
chk "GET after delete -> 404" 404 "$code"

# OPTIONS preflight (204 + CORS)
code=$(curl -s -o "$TD/opt.txt" -D "$TD/opt.hdr" -w '%{http_code}' -X OPTIONS "$B/$HASH")
chk "OPTIONS -> 204" 204 "$code"
grep -qi "access-control-allow-origin: \*" "$TD/opt.hdr" && ok "CORS origin header" || bad "CORS origin header"

# ----------------------------------------------------------------------------
echo ""
echo "================================"
echo "  $PASS passed, $FAIL failed"
echo "================================"
[ "$FAIL" -eq 0 ]
