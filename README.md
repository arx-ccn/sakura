<p align="center">
  <img src="assets/logo.png" width="200" alt="Sakura logo">
</p>

# Sakura

A simple, fast and small [Blossom](https://github.com/hzrd149/blossom) server written in Odin.

## What it implements

| BUD | Coverage |
|-----|----------|
| **BUD-01** | `GET`/`HEAD /<sha256>`, RFC 7233 range requests (`206`, `Content-Range`, `Accept-Ranges`), full CORS, `X-Reason` diagnostics, content sniffing |
| **BUD-02** | `PUT /upload`, blob descriptors, `200`/`201` semantics, `X-SHA-256` check |
| **BUD-04** | `PUT /mirror` (http sources; fetch, hash-verify, store) |
| **BUD-06** | `HEAD /upload` upload-requirements probe (`X-SHA-256`/`X-Content-Length`/`X-Content-Type`) |
| **BUD-11** | `Authorization: Nostr <base64url>` kind-24242 tokens: recomputes the event id, verifies the Schnorr signature, checks `kind`, `created_at`, `expiration`, `t`, `x` and `server` tags |
| **BUD-12** | `GET /list/<pubkey>`, `DELETE /<sha256>` |

## Performance notes

- Reads are lock-free: `GET`/`HEAD` stat and stream blob files straight off disk
  in 64 KiB chunks, and the index mutex is only taken for mutations and metadata.
- Worker threads (one per core) all accept on a single shared listening socket,
  with HTTP keep-alive and request pipelining.
- Each request runs on an arena allocator that is reset afterwards, so parsing
  and response building cause no per-request heap churn.
- secp256k1 verification is variable-time. It touches only public data, so
  constant time isn't needed, and dropping it buys speed. Field reduction
  exploits the `p = 2^256 - 2^32 - 977` shape; scalars and points use 4×`u64`
  limbs with `u128` intermediates.
- SHA-256 is streaming and hashes directly out of the upload buffer.

## Build

```sh
odin build . -out:sakura -o:speed
```

## Run

```sh
SAKURA_PORT=3000 SAKURA_DATA=./data ./sakura
```

Configuration (environment variables):

| Variable | Default | Meaning |
|----------|---------|---------|
| `SAKURA_HOST` | `0.0.0.0` | bind address |
| `SAKURA_PORT` | `3000` | listen port |
| `SAKURA_DATA` | `./data` | blob + index directory |
| `SAKURA_DOMAIN` | _(off)_ | domain for BUD-11 `server`-tag scoping |
| `SAKURA_PUBLIC_URL` | _(derive from Host)_ | base URL in descriptors |
| `SAKURA_MAX_MB` | `100` | max blob size (MB) |
| `SAKURA_WORKERS` | `16` | worker threads |
| `SAKURA_REQUIRE_AUTH` | `true` | require auth for upload/delete/mirror |

## Tests

```sh
./sakura --selftest      # in-binary known-answer tests (47 checks, exit code = result)
./tests/run.sh           # the above + SHA-256 differential + live HTTP end-to-end
```

`--selftest` covers:

- SHA-256: the canonical KATs (empty, `"abc"`, the two NIST multi-block
  vectors) plus the one-million-`'a'` streaming/padding stress.
- secp256k1 units: `fe_inv`/`fe_sqrt`/`fe_neg` round-trips, the published
  x-coordinates of `2G`/`3G`, `(n-1)G == -G`, `2G+G == 3G`, `lift_x(Gx)`.
- BIP-340 verify: all 19 vectors from the spec CSV, including every must-fail
  edge case (off-curve key, `has_even_y(R)` false, negated message/`s`,
  infinite `sG−eP` with `R.x` = 0 and 1, `sig[0:32]` off-curve / `== p`,
  `sig[32:64] == n`, pubkey `> p`) and the 0/1/17/100-byte message vectors.
- BIP-340 sign: byte-exact signatures for the `aux_rand == 0` spec vectors
  (the deterministic case our minter uses).

`tests/run.sh` also diffs `--sha256 <file>` against the system `sha256sum`
across length boundaries (0,1,…55,56,…63,64,65,…127,128,… plus random sizes)
and drives a live server through upload / re-upload / no-auth / wrong-x-tag /
GET / HEAD / range / list / expiry / wrong-verb / delete / OPTIONS.

## Tooling commands

```sh
./sakura --pubkey <seckey_hex>                                # derive x-only pubkey
./sakura --make-token <seckey_hex> <verb> [hash] [exp_unix]   # mint a kind-24242 token
./sakura --sha256 <file>                                      # hash a file (for diffing)
```

Example end-to-end upload:

```sh
HASH=$(sha256sum file.png | cut -d' ' -f1)
TOK=$(./sakura --make-token <seckey> upload "$HASH")
curl -X PUT --data-binary @file.png -H "Authorization: Nostr $TOK" http://localhost:3000/upload
```

## Docker

Because the binary is dependency-free and links fully static, the image is
`FROM scratch`: no base OS, no libc, no shell. The only non-zero layer is the
~1.2 MB stripped binary; everything else is an empty `/data` dir and metadata.

```sh
docker build -t sakura .                                  # downloads Odin, static-builds, runs --selftest
docker run --rm -p 3000:3000 -v sakura-data:/data sakura
```

- The container runs as non-root (`uid 65532`) and persists blobs in the
  `/data` volume; configure it with the same `SAKURA_*` env vars, e.g.
  `-e SAKURA_REQUIRE_AUTH=false`.
- The build stage runs `--selftest` and fails the build if any vector fails.
  Pin the toolchain with `--build-arg ODIN_VERSION=dev-2026-05`.

To test the live image, `tests/docker.sh` builds it, runs a container, drives
the full Blossom flow, and checks persistence across container replacement.
It mints tokens with the image's _own_ CLI, so it validates only the shipped
artifact:

```sh
tests/docker.sh                 # build + black-box test the container
SKIP_BUILD=1 tests/docker.sh    # reuse an already-built image
```

Resulting image is ~1.7 MB locally (≈0.5 MB compressed). To shrink the binary
further you can `upx --best` it in the build stage (≈0.6 MB) at the cost of a
small startup decompression; that's left out by default to keep cold-start
instant.

## Layout

| File | Responsibility |
|------|----------------|
| `sha256.odin` | streaming SHA-256 |
| `secp256k1.odin` | field/scalar/point math, BIP-340 verify + sign |
| `codec.odin` | hex, Base64-URL |
| `json.odin` | JSON parser + NIP-01 string escaping |
| `nostr.odin` | event parsing, id recomputation, BUD-11 validation, token minting |
| `store.odin` | sharded on-disk blob store + append-only index |
| `http.odin` | request parser, response/streaming writer |
| `http_client.odin` | minimal HTTP client for `/mirror` |
| `server.odin` | routing and every endpoint |
| `main.odin` | config, worker pool, self-test, CLI |

## Limitations

- `/mirror` fetches `http://` sources only; TLS is out of scope for a
  dependency-free build, so `https://` sources return `502`.
- BUD-05 (media optimization), BUD-07 (payments), BUD-08/09/10 are not server
  endpoints and are intentionally out of scope.
