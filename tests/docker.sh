#!/usr/bin/env bash
# Black-box test of the live sakura Docker image.
#
# Validates the SHIPPED ARTIFACT: the only crypto/token tooling used is the
# image's own CLI (docker run --rm <img> --make-token ...), so nothing here
# depends on a host-built binary. Host tools used are pure test plumbing
# (curl, sha256sum, xxd).
#
# Usage: tests/docker.sh [image-tag]      (default: sakura)
#        SKIP_BUILD=1 tests/docker.sh     (reuse an already-built image)
set -u

IMG="${1:-sakura}"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$1"; }
chk() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want=$2 got=$3)"; fi; }

command -v docker >/dev/null || { echo "docker not found"; exit 1; }

# ---- build (unless told to skip) ----
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "== building image '$IMG' =="
  docker build --provenance=false --sbom=false -t "$IMG" . >/dev/null 2>&1 \
    && ok "docker build" || { bad "docker build"; echo "build failed"; exit 1; }
fi

echo "== image facts =="
SIZE=$(docker images "$IMG" --format '{{.Size}}' | head -n1)
echo "  image size: $SIZE"
# Final image must be effectively just the binary: assert no shell exists.
if docker run --rm --entrypoint /bin/sh "$IMG" -c 'echo hi' >/dev/null 2>&1; then
  bad "image unexpectedly contains a shell"
else
  ok "no shell in image (scratch confirmed)"
fi

# ---- image-CLI self-test (crypto KATs run *inside* the container) ----
echo "== in-container self-test =="
if docker run --rm "$IMG" --selftest >/tmp/sakura-docker-selftest.out 2>&1; then
  ok "--selftest in container"
else
  bad "--selftest in container"
fi
tail -n1 /tmp/sakura-docker-selftest.out

# ---- helpers that use the IMAGE's own CLI ----
VOL="sakura-test-vol-$$"
PORT=$(( 20000 + (RANDOM % 20000) ))
NAME="sakura-test-$$"

mint()   { docker run --rm "$IMG" --make-token "$@"; }
pubkey() { docker run --rm "$IMG" --pubkey "$1"; }

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1
  docker volume rm "$VOL" >/dev/null 2>&1
}
trap cleanup EXIT

# ---- start the server container ----
echo "== starting container on :$PORT (volume $VOL) =="
docker volume create "$VOL" >/dev/null
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:3000" -v "$VOL:/data" "$IMG" >/dev/null \
  && ok "container started" || { bad "container start"; exit 1; }

B="http://127.0.0.1:$PORT"
# readiness poll (root returns 200)
ready=0
for _ in $(seq 1 50); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/" 2>/dev/null)" = "200" ]; then ready=1; break; fi
  sleep 0.2
done
chk "server reachable" 1 "$ready"
[ "$ready" = "1" ] || { docker logs "$NAME"; echo "server never came up"; exit 1; }

# ---- credentials via the image CLI ----
SECKEY=$(head -c32 /dev/urandom | xxd -p -c64)
PUBKEY=$(pubkey "$SECKEY")
ok "derived pubkey via image: ${PUBKEY:0:16}..."

# ---- full Blossom HTTP flow ----
echo "== HTTP flow against the container =="
printf 'a blob served from a 1.7MB scratch image' > /tmp/dblob.txt
HASH=$(sha256sum /tmp/dblob.txt | cut -d' ' -f1)
UPTOK=$(mint "$SECKEY" upload "$HASH")

code=$(curl -s -o /tmp/ddesc.json -w '%{http_code}' -X PUT --data-binary @/tmp/dblob.txt \
  -H "Authorization: Nostr $UPTOK" -H "Content-Type: text/plain" "$B/upload")
chk "PUT /upload -> 201" 201 "$code"
grep -q "\"sha256\":\"$HASH\"" /tmp/ddesc.json && ok "descriptor sha256" || bad "descriptor sha256"

code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @/tmp/dblob.txt -H "Authorization: Nostr $UPTOK" "$B/upload")
chk "re-upload -> 200" 200 "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @/tmp/dblob.txt "$B/upload")
chk "no-auth upload -> 401" 401 "$code"

curl -s "$B/$HASH" > /tmp/dgot.bin
chk "GET body hash" "$HASH" "$(sha256sum /tmp/dgot.bin | cut -d' ' -f1)"

cl=$(curl -s -I "$B/$HASH" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-length"{print $2}')
chk "HEAD content-length" 40 "$cl"

code=$(curl -s -o /tmp/drange.bin -w '%{http_code}' -H "Range: bytes=2-5" "$B/$HASH")
chk "range -> 206" 206 "$code"
chk "range body" "blob" "$(cat /tmp/drange.bin)"

curl -s "$B/list/$PUBKEY" | grep -q "$HASH" && ok "list contains blob" || bad "list missing blob"

EXP=$(mint "$SECKEY" upload "$HASH" 1000000000)
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @/tmp/dblob.txt -H "Authorization: Nostr $EXP" "$B/upload")
chk "expired token -> 401" 401 "$code"

WV=$(mint "$SECKEY" delete "$HASH")
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @/tmp/dblob.txt -H "Authorization: Nostr $WV" "$B/upload")
chk "wrong-verb token -> 401" 401 "$code"

code=$(curl -s -o /dev/null -D /tmp/opt.hdr -w '%{http_code}' -X OPTIONS "$B/$HASH")
chk "OPTIONS -> 204" 204 "$code"
grep -qi "access-control-allow-origin: \*" /tmp/opt.hdr && ok "CORS header" || bad "CORS header"

# ---- persistence across a fresh container on the same volume ----
echo "== persistence across container replacement =="
docker rm -f "$NAME" >/dev/null
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:3000" -v "$VOL:/data" "$IMG" >/dev/null
for _ in $(seq 1 50); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$B/" 2>/dev/null)" = "200" ] && break; sleep 0.2
done
code=$(curl -s -o /tmp/dgot2.bin -w '%{http_code}' "$B/$HASH")
chk "GET after new container -> 200" 200 "$code"
chk "persisted body hash" "$HASH" "$(sha256sum /tmp/dgot2.bin | cut -d' ' -f1)"
curl -s "$B/list/$PUBKEY" | grep -q "$HASH" && ok "list persisted" || bad "list persisted"

# ---- delete then 404 ----
DEL=$(mint "$SECKEY" delete "$HASH")
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Nostr $DEL" "$B/$HASH")
chk "DELETE -> 200" 200 "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$B/$HASH")
chk "GET after delete -> 404" 404 "$code"

echo ""
echo "================================"
echo "  $PASS passed, $FAIL failed"
echo "================================"
[ "$FAIL" -eq 0 ]
