//! A caching, normalising front end for the ClearlyDefined definitions API.
//!
//! Sits between sbomify-action and api.clearlydefined.io and does three things
//! the client cannot do for itself:
//!
//!   * **absorbs an unreliable upstream** — retries a stall rather than
//!     recording it as "this package has no metadata", which is how a
//!     rate-limited or timed-out lookup silently produced a thinner SBOM;
//!   * **collapses duplicate work** — every user asking about the same package
//!     version shares one upstream fetch, rather than each paying for it;
//!   * **shrinks the answer** — a definition is up to ~190KB of per-file
//!     analysis and consumers read four fields of it.
//!
//! One upstream, on purpose. ClearlyDefined's curated data is CC0-1.0, which is
//! what makes caching and re-serving it unambiguous; the other sources
//! sbomify-action reads carry terms that do not obviously permit the same, and
//! a service that reflected arbitrary paths upstream would be a general proxy
//! for whoever found it. Neither is a gap to be filled later.
//!
//! Designed to sit behind a CDN. The Cache-Control it emits is the useful knob:
//! the edge does the geographic work, this process does the normalising and the
//! collapsing.

mod cache;
mod clearlydefined;
mod persist;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::broadcast;

use cache::Cache;
use clearlydefined::{Client, Coordinate, Definition, FetchError};
use persist::Store;

/// Harvested definitions change only when someone curates them, and the
/// coordinate itself is immutable. Long, but not forever.
const TTL_HARVESTED: Duration = Duration::from_secs(30 * 24 * 3600);
/// An unharvested coordinate is "not looked at yet", not "no licence". It will
/// change, so it must expire soon enough to pick that up.
const TTL_UNHARVESTED: Duration = Duration::from_secs(6 * 3600);

/// How often expired entries are deleted from disk. Nothing else removes them,
/// and nothing depends on it being prompt -- an expired entry is already
/// invisible to reads, it just occupies a page until swept.
const SWEEP_EVERY: Duration = Duration::from_secs(3600);

/// Default on-disk location. A container gets persistence by mounting a volume
/// here and nothing worse than a warning by not doing so.
const DEFAULT_CACHE_PATH: &str = "/var/cache/clearly-cached/definitions.redb";

#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    /// Served from disk after the memory map had evicted or never held it. The
    /// number that says whether the disk tier is earning its keep.
    disk_hits: AtomicU64,
    misses: AtomicU64,
    upstream_errors: AtomicU64,
    /// Requests answered "not yet" because the resolve outlived the client
    /// deadline. The resolve itself keeps running, so these are the ones a
    /// retry is expected to hit warm.
    slow_resolves: AtomicU64,
}

/// Where an answer came from. Reported as `x-cache` so a CDN or an operator can
/// tell an evicted-but-cached coordinate from one that cost an upstream fetch.
#[derive(Debug, Clone, Copy)]
enum Source {
    Memory,
    Disk,
    Upstream,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "HIT",
            Self::Disk => "HIT-DISK",
            Self::Upstream => "MISS",
        }
    }
}

/// A resolve that produced no definition, and the status it deserves.
///
/// Carried rather than flattened to one code: a coordinate upstream rejects is
/// not the same event as an upstream that stalled, and answering both with 504
/// tells a client with retry-on-5xx to keep asking for something that will
/// never exist. Nothing here is cached, so the retry is a fresh upstream fetch
/// every time.
#[derive(Debug, Clone)]
struct Failure {
    status: StatusCode,
    message: String,
}

/// Result shared between everyone waiting on one in-flight resolve.
type Shared = Result<(Definition, Duration, Source), Failure>;

struct AppState {
    cache: Cache<Definition>,
    client: Client,
    stats: Stats,
    /// How long a *request* waits, as opposed to how long the resolve behind
    /// it may run. See the wait in `definition`.
    client_deadline: Duration,
    /// Coordinates currently being fetched, and how to hear the answer.
    ///
    /// The fetch runs in a spawned task rather than inline in the request that
    /// triggered it. That detail is the difference between collapsing working
    /// and collapsing evaporating under load: a client that gives up mid-fetch
    /// cancels its handler, and with an inline fetch that would abandon the
    /// upstream call and let the next waiter start another. Measured before
    /// this change, 30 concurrent requests for one cold coordinate produced 10
    /// upstream fetches instead of 1, precisely because the upstream was slow
    /// enough for callers to time out. Spawning means the work completes and
    /// populates the cache even if every caller has walked away.
    ///
    /// A std lock rather than tokio's: every critical section is a map lookup
    /// with no await in it, and `InflightGuard` has to be able to clear an
    /// entry from `Drop`, which cannot await.
    inflight: std::sync::Mutex<HashMap<String, broadcast::Sender<Arc<Shared>>>>,
    /// The disk tier: everything ever fetched and not yet expired.
    ///
    /// The map above evicts under pressure, this does not. A definition pushed
    /// out of memory is still here, and reading it back costs a disk seek
    /// rather than a round trip to an upstream that stalls on 40% of cold
    /// requests. `None` when the path could not be opened -- persistence is an
    /// optimisation, and refusing to start without it would turn a missing
    /// volume into an outage.
    store: Option<Store<Definition>>,
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let upstream = std::env::var("CLEARLYDEFINED_UPSTREAM")
        .unwrap_or_else(|_| clearlydefined::UPSTREAM.into());
    let capacity = env_u64("CACHE_CAPACITY", 200_000) as usize;
    let attempts = env_u64("UPSTREAM_ATTEMPTS", 3) as u32;
    // Per attempt, and then across all of them. The second is the one that
    // matters to a caller: attempts x timeout was a 45-second worst case, and
    // measured against the deployment cold misses on a stalling coordinate ran
    // past 45s and returned nothing. A client that has already given up is not
    // helped by an answer arriving later.
    let timeout = Duration::from_secs(env_u64("UPSTREAM_TIMEOUT_SECS", 8));
    let deadline = Duration::from_secs(env_u64("UPSTREAM_DEADLINE_SECS", 25));
    // How long a request waits, which is a different question from how long
    // the resolve may take. Because the resolve runs in its own task and
    // publishes to the cache regardless, a caller that stops waiting loses
    // nothing but latency: the answer lands anyway and the next request for
    // that coordinate is a hit.
    //
    // Measured from the client side, a cold lookup had a p50 of 0.56s and a
    // p90 of 20.7s -- the tail being coordinates upstream is slow to produce.
    // The client treats a 504 as transient and moves on, so making it wait
    // twenty more seconds for the same outcome buys nothing. Five seconds is
    // well past the warm case and well short of the deadline.
    let client_deadline = Duration::from_secs(env_u64("CLIENT_DEADLINE_SECS", 5));

    // A client deadline at or above the upstream one is the same as having
    // none: the resolve always answers first, so every caller waits out the
    // full upstream deadline to be told what it could have been told in five
    // seconds. That is a deployment mistake rather than a reason to refuse to
    // start, so say so and carry on -- but say so, because from the outside it
    // is indistinguishable from the bound not existing at all.
    if client_deadline >= deadline {
        eprintln!(
            "config: CLIENT_DEADLINE_SECS ({}s) is not below UPSTREAM_DEADLINE_SECS ({}s), \
             so callers will wait out the resolve instead of being told to retry",
            client_deadline.as_secs(),
            deadline.as_secs()
        );
    }

    let http = reqwest::Client::builder()
        .timeout(timeout)
        // Upstream stalls rather than refusing, so a connect timeout well below
        // the request timeout distinguishes "unreachable" from "thinking".
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!(
            "clearly-cached/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/sbomify/clearly-cached)"
        ))
        .build()
        .expect("failed to build HTTP client");

    // Nothing is preloaded: the disk tier exists so that memory does not have
    // to hold everything, and reading it all back at boot would undo that. The
    // map warms from traffic, and until it does a miss costs a disk read
    // instead of an upstream fetch.
    let store = match cache_path() {
        None => None,
        Some(path) => match Store::open(&path, env_u64("CACHE_DISK_MAX_ENTRIES", 2_000_000)) {
            Ok(store) => {
                eprintln!(
                    "cache: {} entries on disk at {}",
                    store.len(),
                    path.display()
                );
                Some(store)
            }
            Err(e) => {
                // Almost always a missing or unwritable volume. Worth saying
                // loudly, not worth refusing to serve over.
                eprintln!(
                    "cache: running memory-only, cannot use {}: {e}",
                    path.display()
                );
                None
            }
        },
    };

    let state = Arc::new(AppState {
        cache: Cache::new(capacity),
        client: Client::new(http, upstream.clone(), attempts, deadline),
        client_deadline,
        stats: Stats::default(),
        inflight: std::sync::Mutex::new(HashMap::new()),
        store,
    });

    let app = router(state.clone());

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));
    eprintln!(
        "clearly-cached {} listening on {addr}, upstream {upstream}",
        env!("CARGO_PKG_VERSION")
    );

    if state.store.is_some() {
        let state = state.clone();
        tokio::spawn(async move {
            // interval's first tick fires immediately, and that one is kept on
            // purpose: sweeping is the only thing that reclaims expired rows,
            // so a service that redeploys or crash-loops more often than
            // SWEEP_EVERY would otherwise never reach a sweep at all and grow
            // without bound on a persistent volume.
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            loop {
                tick.tick().await;
                if let Some(store) = &state.store {
                    store.sweep();
                }
            }
        });
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");

    // Let queued writes land before the process goes away. Losing them costs
    // only a re-fetch, but there is no reason to lose them on a clean stop.
    if let Some(store) = &state.store {
        store.shutdown();
    }
}

/// Where the cache is persisted. `CACHE_PATH=` (empty) means memory only.
fn cache_path() -> Option<PathBuf> {
    match std::env::var("CACHE_PATH") {
        Ok(p) if p.is_empty() => None,
        Ok(p) => Some(PathBuf::from(p)),
        Err(_) => Some(PathBuf::from(DEFAULT_CACHE_PATH)),
    }
}

/// SIGTERM as well as SIGINT: `docker stop` and every orchestrator send the
/// former, and that is the shutdown that has a cache worth writing out.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
    eprintln!("clearly-cached shutting down");
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        // Mirrors upstream's own path shape, minus the leading /definitions
        // being qualified by anything: there is only one upstream, so a
        // /clearlydefined/ segment would say nothing the service name does not.
        .route(
            "/v1/definitions/{kind}/{provider}/{namespace}/{name}/{revision}",
            get(definition),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/stats", get(stats))
        .with_state(state)
}

/// Counters, and the build they were counted by.
///
/// The version is here because it was the missing fact in a real diagnosis: a
/// deployment reported callers blocking for the full upstream deadline, which
/// the source on the default branch bounds and has a test for. The deployment
/// was a release behind, and nothing it served said so -- the counters, the
/// headers and the error bodies are identical across the two builds. An
/// operator has to be able to ask a running process what it is.
async fn stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "entries": state.cache.len(),
        "disk_entries": state.store.as_ref().map(|s| s.len()),
        "hits": state.stats.hits.load(Ordering::Relaxed),
        "disk_hits": state.stats.disk_hits.load(Ordering::Relaxed),
        "misses": state.stats.misses.load(Ordering::Relaxed),
        "upstream_errors": state.stats.upstream_errors.load(Ordering::Relaxed),
        "slow_resolves": state.stats.slow_resolves.load(Ordering::Relaxed),
    }))
}

async fn definition(
    State(state): State<Arc<AppState>>,
    Path((kind, provider, namespace, name, revision)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    let coord = match Coordinate::parse(&kind, &provider, &namespace, &name, &revision) {
        Ok(c) => c,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let key = coord.cache_key();

    if let Some((def, remaining)) = state.cache.get(&key) {
        state.stats.hits.fetch_add(1, Ordering::Relaxed);
        return serve(def, remaining, Source::Memory);
    }

    // Collapse everything past this point -- the disk read as well as the fetch.
    // Thirty simultaneous requests for one evicted coordinate should be one
    // disk read, for the same reason they should be one upstream fetch.
    let mut receiver = {
        let Ok(mut inflight) = state.inflight.lock() else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "inflight lock poisoned");
        };

        // Re-check under the map lock: the resolve may have finished between
        // the cache miss above and getting here.
        if let Some((def, remaining)) = state.cache.get(&key) {
            state.stats.hits.fetch_add(1, Ordering::Relaxed);
            return serve(def, remaining, Source::Memory);
        }

        match inflight.get(&key) {
            Some(tx) => tx.subscribe(),
            None => {
                let (tx, rx) = broadcast::channel(1);
                inflight.insert(key.clone(), tx);
                spawn_resolve(state.clone(), coord.clone(), key.clone());
                rx
            }
        }
    };

    // Bounded separately from the resolve. The resolve is a detached task
    // that publishes to the cache whatever this request does, so giving up on
    // the wait costs the caller latency and nothing else -- and the retry it
    // is expected to make lands on a warm entry. Waiting the full upstream
    // deadline instead meant a client blocked for twenty-five seconds to be
    // told the same "try again" it could have had in five.
    //
    // The in-flight entry is deliberately left in place: a retry arriving
    // before the resolve finishes subscribes to the same one rather than
    // starting a second fetch for a coordinate upstream is already slow at.
    let waited = tokio::time::timeout(state.client_deadline, receiver.recv()).await;
    let Ok(received) = waited else {
        state.stats.slow_resolves.fetch_add(1, Ordering::Relaxed);
        return error(
            StatusCode::GATEWAY_TIMEOUT,
            "still resolving upstream; the fetch continues and a retry should be served from cache",
        );
    };

    match received {
        Ok(shared) => match &*shared {
            Ok((def, ttl, source)) => serve(def.clone(), *ttl, *source),
            Err(failure) => error(failure.status, &failure.message),
        },
        // Every sender was dropped without publishing, which means the resolve
        // task died -- `InflightGuard` clears the map entry, dropping the last
        // one. Report it rather than leaving this and every later request for
        // the coordinate waiting on a channel that will never send.
        Err(_) => error(StatusCode::BAD_GATEWAY, "resolve task ended unexpectedly"),
    }
}

/// Clears a coordinate from the in-flight map however the resolve ends.
///
/// The map owns the sender, so a task that ends without publishing would
/// otherwise leave a live sender behind: `recv` never errors, and every later
/// request for that coordinate subscribes to a channel nothing will ever send
/// on and waits forever. Removing the entry from `Drop` drops that sender,
/// which turns a dead resolve into an error the caller can see.
struct InflightGuard {
    state: Arc<AppState>,
    key: String,
}

impl InflightGuard {
    /// Take the sender out of the map, leaving nothing for `Drop` to do.
    fn take(&self) -> Option<broadcast::Sender<Arc<Shared>>> {
        self.state.inflight.lock().ok()?.remove(&self.key)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Ok(mut inflight) = self.state.inflight.lock() {
            inflight.remove(&self.key);
        }
    }
}

/// Resolve one coordinate: disk first, upstream if it is not there.
///
/// Detached from any request on purpose -- see `AppState::inflight`.
fn spawn_resolve(state: Arc<AppState>, coord: Coordinate, key: String) {
    tokio::spawn(async move {
        let guard = InflightGuard {
            state: state.clone(),
            key: key.clone(),
        };

        if let Some((def, ttl)) = read_from_disk(&state, &key).await {
            state.stats.disk_hits.fetch_add(1, Ordering::Relaxed);
            // Promote, with the TTL it has left rather than a fresh one: the
            // disk copy expires when it was always going to.
            state.cache.insert(key.clone(), def.clone(), ttl);
            publish(&guard, Ok((def, ttl, Source::Disk)));
            return;
        }

        state.stats.misses.fetch_add(1, Ordering::Relaxed);
        let outcome: Shared = match state.client.fetch(&coord).await {
            Ok(def) => {
                let ttl = if def.harvested {
                    TTL_HARVESTED
                } else {
                    TTL_UNHARVESTED
                };
                state.cache.insert(key.clone(), def.clone(), ttl);
                if let Some(store) = &state.store {
                    store.put(&key, &def, ttl);
                }
                Ok((def, ttl, Source::Upstream))
            }
            Err(FetchError::Upstream(code)) => {
                // Upstream answered definitively, so this is not a retry-me.
                // Pass 404 through as 404 and everything else as 502: a client
                // that retries on 5xx would otherwise loop forever on a
                // coordinate upstream will always reject, since nothing here
                // is cached and every retry is a fresh fetch.
                state.stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                let status = match code {
                    404 => StatusCode::NOT_FOUND,
                    _ => StatusCode::BAD_GATEWAY,
                };
                Err(Failure {
                    status,
                    message: format!("upstream returned {code}"),
                })
            }
            Err(e) => {
                // Transient, and already retried. Never cached -- persisting a
                // stall as "no data" is the failure this service exists to
                // prevent. 504 is honest here: asking again may well work.
                state.stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                Err(Failure {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    message: e.to_string(),
                })
            }
        };

        publish(&guard, outcome);
    });
}

/// Hand the result to everyone waiting and stop collecting new waiters.
///
/// Taken out of the map before publishing, so a request arriving after the
/// result is sent starts a fresh resolve rather than subscribing to a channel
/// that will never send again.
fn publish(guard: &InflightGuard, outcome: Shared) {
    if let Some(tx) = guard.take() {
        let _ = tx.send(Arc::new(outcome));
    }
}

/// Look the coordinate up in the disk tier.
///
/// On a blocking thread: a warm read is a page-cache hit, but a cold one is a
/// disk seek, and the runtime's worker threads are also serving requests.
async fn read_from_disk(state: &Arc<AppState>, key: &str) -> Option<(Definition, Duration)> {
    state.store.as_ref()?;
    let state = state.clone();
    let key = key.to_owned();
    tokio::task::spawn_blocking(move || state.store.as_ref()?.get(&key))
        .await
        .ok()
        .flatten()
}

/// `remaining` is what the entry has left to live, not the TTL it started with.
///
/// The edge TTL follows the same split as the local one -- an unharvested answer
/// must not be pinned at a CDN for a month either -- but it has to shrink with
/// the entry. Re-arming the full constant on every hit would let a CDN hold an
/// entry for up to twice its intended life: an unharvested definition fetched
/// again at five hours fifty-nine would be served as "no licence" for another
/// six, long after upstream had harvested it.
fn serve(def: Definition, remaining: Duration, source: Source) -> Response {
    let max_age = remaining.as_secs();
    (
        StatusCode::OK,
        [
            (
                header::CACHE_CONTROL,
                format!("public, max-age={max_age}, stale-if-error=86400"),
            ),
            (
                header::HeaderName::from_static("x-cache"),
                source.as_str().to_owned(),
            ),
        ],
        Json(def),
    )
        .into_response()
}

fn error(code: StatusCode, message: &str) -> Response {
    (
        code,
        // Never cache an error: a stall cached at the edge would be the same
        // silent data loss, one layer further out.
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// A stand-in for api.clearlydefined.io that counts what reaches it.
    ///
    /// The counter is the point: collapsing and the disk tier are both claims
    /// about how much upstream traffic a burst of requests produces, and
    /// nothing else in the test suite can observe that.
    async fn stub_upstream(hits: Arc<AtomicU64>, delay: Duration, status: StatusCode) -> String {
        let handler = move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::Relaxed);
                // Long enough that callers pile up behind the first fetch
                // rather than arriving after it has already finished.
                tokio::time::sleep(delay).await;
                (
                    status,
                    Json(serde_json::json!({
                        "licensed": {"declared": "MIT"},
                        "described": {"tools": ["scancode/32.7.0"]},
                        "scores": {"effective": 80}
                    })),
                )
            }
        };
        let app = Router::new().route(
            "/definitions/{kind}/{provider}/{namespace}/{name}/{revision}",
            get(handler),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    fn state_for(upstream: String, capacity: usize, disk: Option<PathBuf>) -> Arc<AppState> {
        state_with_deadline(upstream, capacity, disk, Duration::from_secs(30))
    }

    fn state_with_deadline(
        upstream: String,
        capacity: usize,
        disk: Option<PathBuf>,
        deadline: Duration,
    ) -> Arc<AppState> {
        // Long enough not to fire; the tests that care set it explicitly.
        state_with_deadlines(upstream, capacity, disk, deadline, Duration::from_secs(30))
    }

    fn state_with_deadlines(
        upstream: String,
        capacity: usize,
        disk: Option<PathBuf>,
        deadline: Duration,
        client_deadline: Duration,
    ) -> Arc<AppState> {
        Arc::new(AppState {
            cache: Cache::new(capacity),
            client: Client::new(reqwest::Client::new(), upstream, 3, deadline),
            stats: Stats::default(),
            client_deadline,
            inflight: std::sync::Mutex::new(HashMap::new()),
            store: disk.map(|p| Store::open(&p, 0).unwrap()),
        })
    }

    async fn serve_app(state: Arc<AppState>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router(state)).await;
        });
        format!("http://{addr}/v1/definitions")
    }

    fn temp_db() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "clearly-cached-main-{}-{}/definitions.redb",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_requests_for_one_coordinate_cause_one_fetch() {
        // The measured regression this service was built around: with the
        // fetch inline in the handler, 30 concurrent requests for one cold
        // coordinate produced 10 upstream fetches, because callers that time
        // out cancel the handler and abandon the fetch mid-flight.
        let hits = Arc::new(AtomicU64::new(0));
        let upstream =
            stub_upstream(hits.clone(), Duration::from_millis(300), StatusCode::OK).await;
        let base = serve_app(state_for(upstream, 1000, None)).await;

        let url = format!("{base}/npm/npmjs/-/lodash/4.17.21");
        let client = reqwest::Client::new();
        let mut waiting = Vec::new();
        for _ in 0..30 {
            let client = client.clone();
            let url = url.clone();
            waiting.push(tokio::spawn(async move { client.get(url).send().await }));
        }
        for task in waiting {
            let response = task.await.unwrap().unwrap();
            assert_eq!(response.status(), 200);
        }
        assert_eq!(hits.load(Ordering::Relaxed), 1, "collapsing did not hold");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_evicted_coordinate_comes_back_from_disk_not_upstream() {
        let hits = Arc::new(AtomicU64::new(0));
        let upstream = stub_upstream(hits.clone(), Duration::ZERO, StatusCode::OK).await;
        // Capacity of one, so the second coordinate evicts the first.
        let state = state_for(upstream, 1, Some(temp_db()));
        let base = serve_app(state.clone()).await;
        let client = reqwest::Client::new();

        let cache_header = |r: &reqwest::Response| {
            r.headers()
                .get("x-cache")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };

        let first = client
            .get(format!("{base}/npm/npmjs/-/lodash/4.17.21"))
            .send()
            .await
            .unwrap();
        assert_eq!(cache_header(&first), "MISS");

        // Writes are batched onto a background thread, so `put` returns before
        // the row exists and a response saying MISS does not mean the disk
        // tier has it yet. What this test asserts is that an eviction is served
        // from disk rather than upstream, which is only a question once the
        // write has landed -- reading before then measures the queue, not the
        // tier, and turns a slow commit into a failure about caching.
        let key = Coordinate::parse("npm", "npmjs", "-", "lodash", "4.17.21")
            .unwrap()
            .cache_key();
        let store = state
            .store
            .as_ref()
            .expect("the test asked for a disk tier");
        for _ in 0..500 {
            if store.get(&key).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            store.get(&key).is_some(),
            "the queued disk write never landed, so the eviction below cannot be served from disk"
        );

        let second = client
            .get(format!("{base}/pypi/pypi/-/requests/2.32.3"))
            .send()
            .await
            .unwrap();
        assert_eq!(cache_header(&second), "MISS");

        let evicted = client
            .get(format!("{base}/npm/npmjs/-/lodash/4.17.21"))
            .send()
            .await
            .unwrap();
        assert_eq!(cache_header(&evicted), "HIT-DISK");
        assert_eq!(
            hits.load(Ordering::Relaxed),
            2,
            "the evicted coordinate went back upstream"
        );
    }

    /// A caller should not wait out the upstream deadline to be told "later".
    ///
    /// The resolve is a detached task that publishes to the cache whatever the
    /// request does, so giving up on the wait costs latency and nothing else.
    /// Measured from the client side before this, a cold lookup had a p50 of
    /// 0.56s and a p90 of 20.7s; the client treats the 504 as transient either
    /// way, so the extra twenty seconds bought nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_resolve_answers_the_client_before_the_upstream_deadline() {
        let hits = Arc::new(AtomicU64::new(0));
        // Upstream far slower than the client is willing to wait.
        let upstream = stub_upstream(hits.clone(), Duration::from_secs(3), StatusCode::OK).await;
        let state = state_with_deadlines(
            upstream,
            16,
            None,
            Duration::from_secs(30),
            Duration::from_millis(200),
        );
        let base = serve_app(state.clone()).await;

        let started = std::time::Instant::now();
        let response = reqwest::get(format!("{base}/npm/npmjs/-/lodash/4.17.21"))
            .await
            .unwrap();
        let waited = started.elapsed();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(
            waited < Duration::from_secs(2),
            "client waited {waited:?}, which is the upstream's problem rather than its own"
        );
        assert_eq!(state.stats.slow_resolves.load(Ordering::Relaxed), 1);

        // The point of not cancelling: the fetch finishes anyway, so the retry
        // a client is expected to make is served warm.
        tokio::time::sleep(Duration::from_secs(4)).await;
        let retry = reqwest::get(format!("{base}/npm/npmjs/-/lodash/4.17.21"))
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "the abandoned wait must not have caused a second upstream fetch"
        );
    }

    /// An operator must be able to ask a running process which build it is.
    ///
    /// Without this, "the deployment behaves like the old code" and "the
    /// deployment is the old code" cannot be told apart from outside, which is
    /// exactly how a caller-deadline fix sat unreleased while the symptom it
    /// fixed was reported against the branch that already had it.
    #[tokio::test(flavor = "multi_thread")]
    async fn stats_reports_the_running_version() {
        let hits = Arc::new(AtomicU64::new(0));
        let upstream = stub_upstream(hits, Duration::ZERO, StatusCode::OK).await;
        let base = serve_app(state_for(upstream, 16, None)).await;
        let root = base.trim_end_matches("/v1/definitions");

        let body: serde_json::Value = reqwest::get(format!("{root}/stats"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    }

    /// The common case must not pay for the uncommon one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_prompt_resolve_is_served_normally() {
        let hits = Arc::new(AtomicU64::new(0));
        let upstream = stub_upstream(hits.clone(), Duration::from_millis(10), StatusCode::OK).await;
        let state = state_with_deadlines(
            upstream,
            16,
            None,
            Duration::from_secs(30),
            Duration::from_secs(5),
        );
        let base = serve_app(state.clone()).await;

        let response = reqwest::get(format!("{base}/npm/npmjs/-/lodash/4.17.21"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.stats.slow_resolves.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_definitive_upstream_rejection_is_not_reported_as_a_timeout() {
        // 504 means "try again", and nothing here is cached, so a client that
        // retries on 5xx would loop on a coordinate upstream always rejects.
        let hits = Arc::new(AtomicU64::new(0));
        let upstream = stub_upstream(hits.clone(), Duration::ZERO, StatusCode::NOT_FOUND).await;
        let base = serve_app(state_for(upstream, 100, None)).await;

        let response = reqwest::get(format!("{base}/npm/npmjs/-/nope/1.0.0"))
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalling_upstream_is_bounded_by_the_deadline() {
        // Attempts alone do not bound the wait, and a caller that has already
        // given up is not helped by an answer arriving later. Against the
        // deployment this was a 45s worst case that returned nothing.
        let hits = Arc::new(AtomicU64::new(0));
        let upstream = stub_upstream(hits.clone(), Duration::from_secs(60), StatusCode::OK).await;
        let base = serve_app(state_with_deadline(
            upstream,
            100,
            None,
            Duration::from_secs(2),
        ))
        .await;

        let started = std::time::Instant::now();
        let response = reqwest::get(format!("{base}/npm/npmjs/-/stalls/1.0.0"))
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(response.status(), 504);
        assert!(
            elapsed < Duration::from_secs(6),
            "waited {elapsed:?} on a 2s deadline"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_hit_does_not_re_arm_the_full_max_age() {
        let hits = Arc::new(AtomicU64::new(0));
        let upstream = stub_upstream(hits.clone(), Duration::ZERO, StatusCode::OK).await;
        let base = serve_app(state_for(upstream, 100, None)).await;
        let url = format!("{base}/npm/npmjs/-/lodash/4.17.21");

        let max_age = |r: &reqwest::Response| -> u64 {
            let value = r
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            value
                .split(',')
                .find_map(|p| p.trim().strip_prefix("max-age="))
                .and_then(|n| n.parse().ok())
                .unwrap()
        };

        let first = max_age(&reqwest::get(&url).await.unwrap());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let second = max_age(&reqwest::get(&url).await.unwrap());

        assert!(first <= TTL_HARVESTED.as_secs());
        assert!(
            second < first,
            "max-age was re-armed on a hit: {first} then {second}"
        );
    }
}
