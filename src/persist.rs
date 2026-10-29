//! The disk tier of the cache.
//!
//! Memory holds what is hot; this holds everything. Eviction is a memory
//! concern -- a definition pushed out of the map is still on disk, and reading
//! it back costs a page fault rather than a round trip to an upstream that
//! stalls on 40% of cold requests. Nothing is evicted here to make room for
//! something newer; entries leave when they expire, or when the table is over
//! its cap -- which is a backstop against a caller enumerating coordinates,
//! not a working-set limit, since ClearlyDefined answers 200 even for
//! coordinates that do not exist.
//!
//! That split is why this is a real embedded database and not the obvious
//! append-only log. A log has to be indexed to be read from at random, and an
//! in-memory index over every key on disk reintroduces exactly the memory
//! ceiling the split exists to escape -- smaller by a constant, unbounded all
//! the same. redb keeps its B-tree on disk and its page cache bounded, so the
//! process footprint stops depending on how much has ever been cached.
//!
//! Writes are batched onto one background thread. Each is ~0.4KB and arrives on
//! a cache miss, so committing per entry would fsync once per upstream fetch to
//! save work that a crash makes us redo anyway. Losing the last batch costs a
//! re-fetch, which is the thing this is a cache for.
//!
//! An entry outlives its expiry by a grace period, during which it is read back
//! as stale rather than not at all. See `Found`.

use std::collections::BinaryHeap;
use std::ops::Bound;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const DEFINITIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("definitions");

/// How many queued writes are folded into one transaction.
const BATCH: usize = 512;

/// Keys deleted per transaction during a sweep or an eviction.
const SWEEP_BATCH: usize = 4096;

/// Rows examined before a sweep pass yields, so one pass over a huge table
/// neither holds a read transaction open indefinitely nor buffers without end.
const SCAN_BATCH: usize = 100_000;

/// Most entries one sweep will evict for size. A cap this far above normal
/// churn only bites when something is filling the table deliberately, and
/// bounding it keeps the eviction heap small.
const EVICT_BATCH: usize = 50_000;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// What a lookup found.
pub enum Found<V> {
    /// Live, with the TTL it has left.
    Fresh(V, Duration),
    /// Expired but inside the grace period, with the grace it has left. Worth
    /// answering with while it is refetched, and not worth anything more.
    Stale(V, Duration),
}

/// A stored value and when it stops being one.
#[derive(Serialize, Deserialize)]
struct Record<V> {
    /// Absolute Unix expiry, not a TTL. The point of persisting is to survive a
    /// process that is not running, and a duration relative to insertion is
    /// meaningless once nobody is left to remember when insertion was.
    e: u64,
    v: V,
}

enum Msg {
    Put(String, Vec<u8>),
    /// Delete everything expired. Nothing else removes entries, so without this
    /// the file only grows.
    Sweep,
    Shutdown,
}

pub struct Store<V> {
    db: Arc<Database>,
    tx: Sender<Msg>,
    /// Taken by whichever call to `shutdown` gets there first. Behind a lock
    /// because the store lives in shared state and shutdown only borrows it.
    writer: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Seconds past expiry an entry is kept and readable as stale.
    grace: u64,
    _marker: std::marker::PhantomData<fn() -> V>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<V: Serialize + DeserializeOwned> Store<V> {
    /// `max_entries` is the ceiling the sweep evicts back down to; 0 disables
    /// it. Unlike the memory cache there is no eviction on the write path --
    /// disk is meant to keep what it is given -- so this is what stops a caller
    /// enumerating coordinates until the volume is full.
    ///
    /// `grace` is how long past expiry an entry is kept, readable through
    /// `lookup` as stale; the sweep removes it only after that.
    pub fn open(path: &Path, max_entries: u64, grace: Duration) -> Result<Self, Error> {
        let grace = grace.as_secs();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Arc::new(Database::create(path)?);

        // Creating the table up front means every later read can open it rather
        // than handling "no table yet" as a distinct case.
        let txn = db.begin_write()?;
        txn.open_table(DEFINITIONS)?;
        txn.commit()?;

        let (tx, rx) = mpsc::channel();
        let writer_db = db.clone();
        let writer = std::thread::Builder::new()
            .name("cache-writer".into())
            .spawn(move || run_writer(writer_db, rx, max_entries, grace))?;

        Ok(Self {
            db,
            tx,
            writer: std::sync::Mutex::new(Some(writer)),
            grace,
            _marker: std::marker::PhantomData,
        })
    }

    /// The value and the TTL it has left, or `None` if absent or expired --
    /// stale included. The service reads through `lookup`; this is the shape
    /// the tests want.
    #[cfg(test)]
    pub fn get(&self, key: &str) -> Option<(V, Duration)> {
        match self.lookup(key)? {
            Found::Fresh(v, ttl) => Some((v, ttl)),
            Found::Stale(..) => None,
        }
    }

    /// The entry, fresh or inside its grace period, or `None` if absent or
    /// past both.
    ///
    /// Blocking. Callers on an async runtime must run it on a blocking thread:
    /// a warm read is a page-cache hit but a cold one is a disk seek.
    pub fn lookup(&self, key: &str) -> Option<Found<V>> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(DEFINITIONS).ok()?;
        let bytes = table.get(key).ok()??;
        let record: Record<V> = serde_json::from_slice(bytes.value()).ok()?;
        let now = unix_now();
        if record.e > now {
            return Some(Found::Fresh(record.v, Duration::from_secs(record.e - now)));
        }
        let forget_at = record.e.saturating_add(self.grace);
        if forget_at <= now {
            // Left for the sweep rather than deleted here: a read should not
            // need a write transaction, and the entry is already invisible.
            return None;
        }
        Some(Found::Stale(record.v, Duration::from_secs(forget_at - now)))
    }

    /// Queue a write. Never blocks the caller on disk.
    pub fn put(&self, key: &str, value: &V, ttl: Duration) {
        let record = Record {
            e: unix_now() + ttl.as_secs(),
            v: value,
        };
        if let Ok(bytes) = serde_json::to_vec(&record) {
            let _ = self.tx.send(Msg::Put(key.to_owned(), bytes));
        }
    }

    pub fn sweep(&self) {
        let _ = self.tx.send(Msg::Sweep);
    }

    pub fn len(&self) -> u64 {
        self.db
            .begin_read()
            .ok()
            .and_then(|txn| txn.open_table(DEFINITIONS).ok())
            .and_then(|t| t.len().ok())
            .unwrap_or(0)
    }

    /// Flush queued writes and stop the writer. Idempotent, and implied by
    /// dropping the store -- explicit at shutdown only so a clean stop waits
    /// for the queue rather than racing the process exit.
    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
        let handle = self.writer.lock().ok().and_then(|mut w| w.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl<V> Drop for Store<V> {
    fn drop(&mut self) {
        // The writer holds a clone of the database handle, and redb keeps the
        // file locked until the last one goes. Joining here is what makes the
        // path reusable -- by a test, or by a process that reopens it.
        let _ = self.tx.send(Msg::Shutdown);
        let handle = self.writer.lock().ok().and_then(|mut w| w.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

fn run_writer(db: Arc<Database>, rx: Receiver<Msg>, max_entries: u64, grace: u64) {
    let mut pending: Vec<(String, Vec<u8>)> = Vec::new();

    // Ends when every sender is gone, which happens when the store is dropped.
    while let Ok(msg) = rx.recv() {
        match msg {
            Msg::Put(key, bytes) => {
                pending.push((key, bytes));
                // Take whatever else is already queued, so a burst of misses
                // costs one transaction rather than one each.
                while pending.len() < BATCH {
                    match rx.try_recv() {
                        Ok(Msg::Put(k, b)) => pending.push((k, b)),
                        Ok(Msg::Sweep) => {
                            commit(&db, &mut pending);
                            sweep(&db, max_entries, grace);
                        }
                        Ok(Msg::Shutdown) => {
                            commit(&db, &mut pending);
                            return;
                        }
                        Err(_) => break,
                    }
                }
                commit(&db, &mut pending);
            }
            Msg::Sweep => sweep(&db, max_entries, grace),
            Msg::Shutdown => break,
        }
    }
    commit(&db, &mut pending);
}

fn commit(db: &Database, pending: &mut Vec<(String, Vec<u8>)>) {
    if pending.is_empty() {
        return;
    }
    let result = (|| -> Result<(), Error> {
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(DEFINITIONS)?;
            for (key, bytes) in pending.iter() {
                table.insert(key.as_str(), bytes.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    })();
    if let Err(e) = result {
        // A failed write costs a re-fetch later. Nothing to recover, but a
        // silently read-only cache is worth knowing about.
        eprintln!("cache: could not persist {} entries: {e}", pending.len());
    }
    pending.clear();
}

/// Delete entries past their grace period, then anything over the size cap.
///
/// Both passes work in bounded batches. Collecting every expired key first and
/// deleting them in one transaction is simpler, but on a multi-million-row
/// table that is hundreds of megabytes of keys plus the transaction's dirty
/// pages held in this thread -- which is the unbounded memory the disk tier
/// exists to avoid, arriving by another route.
fn sweep(db: &Database, max_entries: u64, grace: u64) {
    // An entry is only gone once its grace period is; until then it is the
    // stale answer a slow refetch is covered by.
    let now = unix_now().saturating_sub(grace);
    let mut cursor: Option<String> = None;
    let mut removed = 0usize;

    loop {
        let (batch, next) = match scan_expired(db, now, cursor.as_deref()) {
            Ok(found) => found,
            Err(e) => {
                eprintln!("cache: sweep scan failed: {e}");
                return;
            }
        };
        if !batch.is_empty() {
            match delete(db, &batch) {
                Ok(()) => removed += batch.len(),
                Err(e) => {
                    eprintln!("cache: sweep failed: {e}");
                    return;
                }
            }
        }
        match next {
            Some(k) => cursor = Some(k),
            None => break,
        }
    }
    if removed > 0 {
        eprintln!("cache: swept {removed} expired entries");
    }

    evict_to_cap(db, max_entries);
}

/// One bounded pass of the table from `after`, returning expired keys and where
/// to resume. `None` for the resume point means the end of the table.
fn scan_expired(
    db: &Database,
    now: u64,
    after: Option<&str>,
) -> Result<(Vec<String>, Option<String>), Error> {
    let txn = db.begin_read()?;
    let table = txn.open_table(DEFINITIONS)?;
    let range: (Bound<&str>, Bound<&str>) = match after {
        Some(k) => (Bound::Excluded(k), Bound::Unbounded),
        None => (Bound::Unbounded, Bound::Unbounded),
    };

    let mut expired = Vec::new();
    let mut last: Option<String> = None;
    let mut scanned = 0usize;
    for row in table.range::<&str>(range)? {
        let (key, value) = row?;
        last.replace(key.value().to_owned());
        scanned += 1;
        // Only the expiry is needed, and it is the first field, so the
        // definition itself is never deserialised during a sweep.
        if let Ok(head) = serde_json::from_slice::<Expiry>(value.value()) {
            if head.e <= now {
                expired.push(key.value().to_owned());
            }
        }
        if expired.len() >= SWEEP_BATCH || scanned >= SCAN_BATCH {
            return Ok((expired, last));
        }
    }
    Ok((expired, None))
}

/// Drop the soonest-to-expire entries until the table is back under its cap.
///
/// The cap is the only bound on the disk tier. ClearlyDefined answers 200 for
/// coordinates that do not exist, so without one a caller looping over random
/// names writes a row per request until the volume fills and every later commit
/// fails. Soonest-expiry-first because those entries were going to be re-fetched
/// first anyway.
fn evict_to_cap(db: &Database, max_entries: u64) {
    if max_entries == 0 {
        return; // Explicitly unbounded.
    }
    let live = match count(db) {
        Ok(n) => n,
        Err(_) => return,
    };
    if live <= max_entries {
        return;
    }
    let excess = ((live - max_entries) as usize).min(EVICT_BATCH);

    // A max-heap holding the `excess` smallest expiries seen: bounded memory
    // over an unbounded table, unlike sorting the whole thing.
    let victims = (|| -> Result<Vec<String>, Error> {
        let txn = db.begin_read()?;
        let table = txn.open_table(DEFINITIONS)?;
        let mut heap: BinaryHeap<(u64, String)> = BinaryHeap::with_capacity(excess + 1);
        for row in table.iter()? {
            let (key, value) = row?;
            let Ok(head) = serde_json::from_slice::<Expiry>(value.value()) else {
                continue;
            };
            if heap.len() < excess {
                heap.push((head.e, key.value().to_owned()));
            } else if heap.peek().is_some_and(|(worst, _)| head.e < *worst) {
                heap.pop();
                heap.push((head.e, key.value().to_owned()));
            }
        }
        Ok(heap.into_iter().map(|(_, k)| k).collect())
    })();

    let Ok(victims) = victims else { return };
    for chunk in victims.chunks(SWEEP_BATCH) {
        if let Err(e) = delete(db, chunk) {
            eprintln!("cache: eviction failed: {e}");
            return;
        }
    }
    eprintln!(
        "cache: evicted {} entries over the {max_entries} cap",
        victims.len()
    );
}

fn count(db: &Database) -> Result<u64, Error> {
    let txn = db.begin_read()?;
    Ok(txn.open_table(DEFINITIONS)?.len()?)
}

fn delete(db: &Database, keys: &[String]) -> Result<(), Error> {
    let txn = db.begin_write()?;
    {
        let mut table = txn.open_table(DEFINITIONS)?;
        for key in keys {
            table.remove(key.as_str())?;
        }
    }
    txn.commit()?;
    Ok(())
}

/// Just the expiry, for sweeping without paying to parse the value.
#[derive(Deserialize)]
struct Expiry {
    e: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "clearly-cached-test-{}-{}/definitions.redb",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// Close one store and reopen the same file, the way a restart would.
    fn restart(store: Store<String>, path: &Path) -> Store<String> {
        drop(store); // Releases redb's file lock once the writer has joined.
        Store::<String>::open(path, 0, Duration::ZERO).unwrap()
    }

    #[test]
    fn survives_a_restart() {
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::ZERO).unwrap();
        store.put(
            "npm/npmjs/-/lodash/4.17.21",
            &"MIT".into(),
            Duration::from_secs(600),
        );

        let store = restart(store, &path);
        let (value, ttl) = store.get("npm/npmjs/-/lodash/4.17.21").unwrap();
        assert_eq!(value, "MIT");
        // Remaining, not original: a restart must not extend the life of an
        // entry that was nearly expired when it was written.
        assert!(ttl <= Duration::from_secs(600));
    }

    #[test]
    fn an_expired_entry_is_not_returned() {
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::ZERO).unwrap();
        store.put("stale", &"x".into(), Duration::from_secs(0));
        store.put("fresh", &"y".into(), Duration::from_secs(600));

        let store = restart(store, &path);
        assert!(store.get("stale").is_none());
        assert!(store.get("fresh").is_some());
    }

    #[test]
    fn sweeping_removes_expired_entries_and_keeps_live_ones() {
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::ZERO).unwrap();
        for i in 0..10 {
            store.put(&format!("stale{i}"), &"x".into(), Duration::from_secs(0));
        }
        store.put("live", &"y".into(), Duration::from_secs(600));
        store.sweep();

        let store = restart(store, &path);
        assert_eq!(store.len(), 1, "expired entries were not swept");
        assert!(store.get("live").is_some());
    }

    #[test]
    fn a_repeated_key_keeps_the_later_value() {
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::ZERO).unwrap();
        store.put("k", &"old".into(), Duration::from_secs(600));
        store.put("k", &"new".into(), Duration::from_secs(600));

        let store = restart(store, &path);
        assert_eq!(store.get("k").unwrap().0, "new");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_missing_key_is_absent_not_an_error() {
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::ZERO).unwrap();
        assert!(store.get("never-written").is_none());
    }

    #[test]
    fn an_expired_entry_is_stale_within_the_grace_period() {
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::from_secs(600)).unwrap();
        store.put("k", &"x".into(), Duration::from_secs(0));
        drop(store);
        let store = Store::<String>::open(&path, 0, Duration::from_secs(600)).unwrap();

        assert!(store.get("k").is_none(), "a stale entry was read as fresh");
        match store.lookup("k") {
            Some(Found::Stale(v, left)) => {
                assert_eq!(v, "x");
                assert!(left <= Duration::from_secs(600));
            }
            _ => panic!("an entry inside its grace period was not found as stale"),
        }
    }

    #[test]
    fn sweeping_keeps_entries_inside_their_grace_period() {
        // The sweep is what would otherwise take a stale answer away before a
        // refetch has replaced it.
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::from_secs(600)).unwrap();
        store.put("k", &"x".into(), Duration::from_secs(0));
        store.sweep();
        drop(store);
        let store = Store::<String>::open(&path, 0, Duration::from_secs(600)).unwrap();
        assert_eq!(store.len(), 1);
        assert!(matches!(store.lookup("k"), Some(Found::Stale(..))));
    }

    #[test]
    fn sweeping_evicts_down_to_the_cap() {
        // Nothing bounds the disk tier on the write path, so without this the
        // table grows for as long as a caller keeps naming new coordinates.
        let path = temp_path();
        let store = Store::<String>::open(&path, 10, Duration::ZERO).unwrap();
        for i in 0..100 {
            // Ascending TTLs, so the soonest-to-expire are the low indices.
            store.put(
                &format!("k{i:03}"),
                &"v".into(),
                Duration::from_secs(600 + i),
            );
        }
        store.sweep();

        let store = restart(store, &path);
        assert_eq!(store.len(), 10, "table was not evicted to the cap");
        // Soonest-expiry-first: those were going to be re-fetched first anyway.
        assert!(store.get("k000").is_none(), "kept a soonest-expiring entry");
        assert!(store.get("k099").is_some(), "dropped a longest-lived entry");
    }

    #[test]
    fn a_zero_cap_means_unbounded() {
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::ZERO).unwrap();
        for i in 0..50 {
            store.put(&format!("k{i}"), &"v".into(), Duration::from_secs(600));
        }
        store.sweep();

        let store = restart(store, &path);
        assert_eq!(store.len(), 50);
    }

    #[test]
    fn a_write_queued_at_shutdown_is_not_lost() {
        // The batching writer is why this needs a test: a put returns before
        // the transaction commits, so a stop that does not drain the queue
        // silently drops whatever was in it.
        let path = temp_path();
        let store = Store::<String>::open(&path, 0, Duration::ZERO).unwrap();
        for i in 0..1000 {
            store.put(&format!("k{i}"), &format!("v{i}"), Duration::from_secs(600));
        }

        let store = restart(store, &path);
        assert_eq!(store.len(), 1000);
        assert_eq!(store.get("k999").unwrap().0, "v999");
    }
}
