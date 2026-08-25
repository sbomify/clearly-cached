# clearly-cached

A caching, normalising front end for the
[ClearlyDefined](https://clearlydefined.io) definitions API, built for
[sbomify-action](https://github.com/sbomify/sbomify-action).

## Why

Three problems, none of which the client can solve for itself.

**The upstream is unreliable.** Sampled from one host, roughly 40% of cold
requests to `api.clearlydefined.io` returned nothing within 10 seconds — and
every one of those succeeded on retry within a second. A client that gives up
after one attempt records "this package has no metadata", which is indistinguishable
in the output from a package that genuinely has none. The result is an SBOM
that is quietly less complete, with nothing failing to say so.

**The same work is repeated everywhere.** Every user scanning a project that
depends on `lodash@4.17.21` asks the same question. One fetch can answer all of
them.

**The answers are enormous.** A definition carries a per-file analysis:
`lodash@4.17.21` is 189KB. Consumers read four fields totalling about 440 bytes
— a licence expression, the curated copyright holders, a homepage and a
repository URL. Caching 189KB to serve 0.2% of it wastes bandwidth at the edge
and parse time in every client.

| | per coordinate |
| --- | ---: |
| upstream definition | 18–190 KB |
| this service | **~0.4 KB** |

## API

```
GET /v1/definitions/{type}/{provider}/{namespace}/{name}/{revision}
```

The path mirrors ClearlyDefined's own coordinates, including `-` for an absent
namespace. The response does not: it is the projection, not the definition.

```console
$ curl https://…/v1/definitions/pypi/pypi/-/requests/2.32.3
{
  "declared": "Apache-2.0",
  "parties": ["Copyright Kenneth Reitz"],
  "homepage": null,
  "source_url": null,
  "harvested": true,
  "score": 73
}
```

`harvested` is the field worth understanding. **ClearlyDefined never 404s** — a
coordinate nobody has looked at yet returns `200` with an empty definition and a
score around 35, which is indistinguishable from "this package genuinely has no
licence" unless you check whether any tools ran. `harvested: false` means *not
examined yet*, and it will change. Treat it accordingly rather than recording it
as an absence.

Also available: `GET /healthz`, `GET /stats`.

## Behaviour

**Retries transient failures, within a deadline.** Timeouts, 429s and 5xx are
retried with a short linear backoff, but never past `UPSTREAM_DEADLINE_SECS` in
total — attempts alone are not a bound, and a caller that has already given up
is not helped by an answer arriving later. Nothing transient is ever cached:
persisting a stall as "no data" is the failure this service exists to prevent.

**Collapses concurrent misses.** Thirty simultaneous requests for one cold
coordinate produce one upstream fetch. The fetch runs detached from the request
that triggered it, so a client that gives up does not abandon the work — without
that, collapsing evaporates exactly when the upstream is slow enough to matter.
Measured before that fix: 30 concurrent requests, 10 upstream fetches.

**Splits the TTL by harvest state.** A harvested definition is held for 30 days;
the coordinate is immutable and only a curation changes it. An unharvested one
is held for 6 hours, so a package harvested tomorrow is not remembered as empty
for a month. The `Cache-Control` sent to any CDN in front follows the same
split, and counts down with the entry rather than re-arming on each hit — a full
`max-age` on a nearly-expired entry would let the edge hold it for twice its
intended life.

**Reports upstream rejections as rejections.** A coordinate upstream refuses
comes back as `404`, not `504`. Nothing here is cached, so answering a permanent
error with a retry-me status would put a retrying client in a loop against an
answer that will never change.

**Forwards only known coordinates.** Type/provider pairs are an allow-list.
Without one, any path under `/v1/` is reflected into an upstream URL and this
becomes a general-purpose proxy for whoever finds it.

## The two tiers

Memory holds what is hot. Disk holds everything.

Eviction is a memory concern: when the map is full the oldest entries go, but
they are still on disk, and reading one back is a local seek rather than a round
trip to an upstream that stalls on 40% of cold requests. Disk keeps what it is
given — entries leave when they expire, swept hourly and once at startup.

| | memory | disk |
| --- | --- | --- |
| holds | `CACHE_CAPACITY` entries | everything unexpired |
| evicts | yes, when full | only over `CACHE_DISK_MAX_ENTRIES` |
| survives a restart | no | yes |
| typical read | ~1 µs | ~100 µs |

The disk cap is a backstop, not a working-set limit. ClearlyDefined answers 200
for coordinates that do not exist, so without one a caller looping over random
names writes a row per request until the volume fills; over the cap the sweep
drops the soonest-to-expire entries, which were going to be re-fetched first
anyway. Set it to `0` for genuinely unbounded.

The `x-cache` header says which answered: `HIT` from memory, `HIT-DISK` from
disk, `MISS` when it went upstream. `/stats` reports the same split, and
`disk_hits` is the number that says whether the disk tier is earning its keep.

Concurrent requests for one cold coordinate collapse onto a single resolve, so
thirty simultaneous callers cause one disk read, or one upstream fetch, not
thirty.

The disk tier is [redb](https://github.com/cberner/redb) — pure Rust, no C, and
it keeps its index on disk. An append-only log would have been less code, but
reading from it at random needs an in-memory index over every key, which
reintroduces the memory ceiling the split exists to escape. Writes are batched
onto a background thread and never block a response; losing the last batch to a
power cut costs a re-fetch, which is what a cache is for.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Listen address |
| `CLEARLYDEFINED_UPSTREAM` | `https://api.clearlydefined.io` | Upstream base URL |
| `CACHE_PATH` | `/var/cache/clearly-cached/definitions.redb` | Disk tier; set empty for memory only |
| `CACHE_CAPACITY` | `200000` | Entries held in memory before eviction |
| `CACHE_DISK_MAX_ENTRIES` | `2000000` | Disk ceiling; `0` for unbounded |
| `UPSTREAM_ATTEMPTS` | `3` | Total attempts per fetch |
| `UPSTREAM_TIMEOUT_SECS` | `8` | Per-attempt timeout |
| `UPSTREAM_DEADLINE_SECS` | `25` | Ceiling across all attempts |
| `CLIENT_DEADLINE_SECS` | `5` | How long a *request* waits. The resolve behind it keeps running and still populates the cache, so a caller that gives up loses latency rather than the answer |

`CLIENT_DEADLINE_SECS` only does anything below `UPSTREAM_DEADLINE_SECS`. Set at
or above it, the resolve always answers first and every caller waits out the
upstream deadline to be told to retry — the bound is still there, it just never
fires. The service says so at startup rather than refusing to run.

If `CACHE_PATH` cannot be opened the service logs it and runs memory-only rather
than refusing to start — a missing volume should not be an outage.

## Which build is running

`/stats` reports the version alongside the counters, and the same version is on
the startup line.

```console
$ curl -s https://…/stats | jq .version
"0.3.0"
```

Worth checking before reading behaviour as a bug: the counters, the `x-cache`
header and the error bodies are identical across releases, so a deployment a
release behind is indistinguishable from a live one by anything else it serves.

## Running

```console
$ docker run -p 8080:8080 \
    -v clearly-cached:/var/cache/clearly-cached \
    ghcr.io/sbomify/clearly-cached:latest
```

The volume is what makes the disk tier outlive the container. Without one the
cache still survives a restart, but not a `docker rm`.

The image is a static musl binary on `scratch` — about 6.5MB, no shell, no
package manager, running as uid 65532. TLS roots are compiled in, so there is
no system certificate store to mount.

`linux/amd64` and `linux/arm64` are both published under the same tags, so a
pull resolves to the right one. Each is built on a native runner rather than
under emulation.

### Without Docker

Static binaries for both architectures are attached to every release, and to
every CI run as artifacts:

```console
$ curl -fsSLO https://github.com/sbomify/clearly-cached/releases/latest/download/clearly-cached-x86_64-unknown-linux-musl
$ chmod +x clearly-cached-*
$ CACHE_PATH=./definitions.redb ./clearly-cached-x86_64-unknown-linux-musl
```

They link nothing — no libc, no OpenSSL — so they run on any Linux of the right
architecture. Swap `x86_64` for `aarch64` on arm64.

It is designed to sit behind a CDN. The edge does the geographic work; this
process does the normalising and the collapsing.

### Verifying it

Every pushed image carries a [SLSA v1 build-provenance
attestation](https://github.com/actions/attest-build-provenance), signed through
the public-good Sigstore instance and recorded in the public transparency log.

```console
$ gh attestation verify oci://ghcr.io/sbomify/clearly-cached:latest \
    --repo sbomify/clearly-cached

$ gh attestation verify ./clearly-cached-aarch64-unknown-linux-musl \
    --repo sbomify/clearly-cached
```

That binds the digest to the workflow, commit and runner that produced it. For
the image it is the manifest list that is attested — what a tag actually
resolves to — and the image is `scratch` plus one static binary, so verifying it
verifies the binary. The image attestation is pushed to the registry alongside
the image, so `cosign verify-attestation` works against a pull alone, without
consulting the GitHub API.

## Scope

One upstream, deliberately. Re-serving someone else's data is a licensing
question, and ClearlyDefined is the source where the answer is unambiguous: its
curated data is [CC0-1.0](https://github.com/clearlydefined/curated-data/blob/master/LICENSE),
a public domain dedication that explicitly covers database rights and permits
redistribution for any purpose.

That does not generalise, which is why nothing else is served here.
`ecosyste.ms` publishes its data under CC BY-SA 4.0, carrying attribution and
share-alike obligations alongside a commercial licensing offer. Repology asks
bulk consumers to use its database dumps rather than the API. `deps.dev`
publishes no data licence at all. Those sources need their own answers, and
probably their own services — not a second backend behind this one.

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE).
