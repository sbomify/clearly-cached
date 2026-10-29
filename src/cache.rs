//! A bounded TTL map with request collapsing.
//!
//! Two properties matter here and neither is about raw speed.
//!
//! **Collapsing.** A newly published package is asked for by every CI job that
//! depends on it, at once. Without collapsing, one cold coordinate becomes N
//! simultaneous upstream requests against the endpoint that already stalls
//! under load. The first caller fetches; the rest wait and read the result.
//!
//! **A TTL that depends on the answer.** ClearlyDefined never 404s: an
//! unharvested coordinate returns 200 with an empty definition, indistinguishable
//! from "this package genuinely has no licence" unless you look at whether any
//! tools ran. Caching that for a month would freeze "no data" over a package
//! that gets harvested tomorrow, so the caller picks the TTL per entry.
//!
//! **Expiry is not forgetting.** An expired entry is kept for a grace period
//! and handed out as stale while it is refetched. Upstream is slowest on
//! exactly the coordinates it has not harvested -- the ones with the short TTL
//! -- so dropping them on expiry made every caller after the sixth hour wait
//! out a stall for an answer this process already had.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

struct Entry<V> {
    value: V,
    expires_at: Instant,
    /// When the entry stops being worth serving even as stale.
    forget_at: Instant,
}

pub struct Cache<V> {
    entries: RwLock<HashMap<String, Entry<V>>>,
    capacity: usize,
    /// How long past expiry an entry may still be served as stale.
    grace: Duration,
}

impl<V: Clone> Cache<V> {
    pub fn new(capacity: usize, grace: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            capacity,
            grace,
        }
    }

    /// The value and the TTL it has left.
    ///
    /// The remaining lifetime is returned, not just the value, because it ends
    /// up in `Cache-Control`: answering a hit with a fresh full TTL would let a
    /// CDN hold an entry for up to twice as long as it is meant to live.
    pub fn get(&self, key: &str) -> Option<(V, Duration)> {
        let entries = self.entries.read().ok()?;
        let entry = entries.get(key)?;
        let now = Instant::now();
        if entry.expires_at <= now {
            return None;
        }
        Some((entry.value.clone(), entry.expires_at - now))
    }

    /// An expired entry still inside its grace period.
    ///
    /// Only for answering while a refetch is under way: the caller must not
    /// treat it as fresh, and nothing about it should be re-cached downstream.
    pub fn get_stale(&self, key: &str) -> Option<V> {
        let entries = self.entries.read().ok()?;
        let entry = entries.get(key)?;
        let now = Instant::now();
        if entry.expires_at > now || entry.forget_at <= now {
            return None;
        }
        Some(entry.value.clone())
    }

    pub fn insert(&self, key: String, value: V, ttl: Duration) {
        let expires_at = Instant::now() + ttl;
        self.put(key, value, expires_at, expires_at + self.grace);
    }

    /// Hold an already-expired value for the `grace_left` it has remaining,
    /// so the next caller is answered from memory while it is refetched. This
    /// is how a stale entry read back from disk is promoted.
    pub fn insert_stale(&self, key: String, value: V, grace_left: Duration) {
        let now = Instant::now();
        self.put(key, value, now, now + grace_left);
    }

    fn put(&self, key: String, value: V, expires_at: Instant, forget_at: Instant) {
        let Ok(mut entries) = self.entries.write() else {
            // A poisoned lock means a panic while holding it. Losing the cache
            // is survivable; refusing to serve is not.
            return;
        };
        if entries.len() >= self.capacity {
            let now = Instant::now();
            entries.retain(|_, e| e.forget_at > now);
            if entries.len() >= self.capacity {
                // Still full of live entries. Drop an arbitrary tenth rather
                // than sorting by age: this only happens when the working set
                // genuinely exceeds capacity, and an approximation is enough
                // to keep serving.
                let excess = self.capacity / 10 + 1;
                let victims: Vec<String> = entries.keys().take(excess).cloned().collect();
                for k in victims {
                    entries.remove(&k);
                }
            }
        }
        entries.insert(
            key,
            Entry {
                value,
                expires_at,
                forget_at,
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_a_live_entry() {
        let c: Cache<u32> = Cache::new(10, Duration::ZERO);
        c.insert("k".into(), 1, Duration::from_secs(60));
        assert_eq!(c.get("k").map(|(v, _)| v), Some(1));
    }

    #[test]
    fn reports_remaining_lifetime_not_the_original_ttl() {
        // This is what ends up in Cache-Control, so a hit late in an entry's
        // life must not hand a CDN a fresh full TTL.
        let c: Cache<u32> = Cache::new(10, Duration::ZERO);
        c.insert("k".into(), 1, Duration::from_millis(60));
        std::thread::sleep(Duration::from_millis(20));
        let (_, remaining) = c.get("k").expect("entry expired early");
        assert!(
            remaining < Duration::from_millis(60),
            "TTL did not decay: {remaining:?}"
        );
    }

    #[test]
    fn does_not_return_an_expired_entry() {
        let c: Cache<u32> = Cache::new(10, Duration::ZERO);
        c.insert("k".into(), 1, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(c.get("k"), None);
    }

    #[test]
    fn expiry_is_per_entry_not_global() {
        // The whole point of the split TTL: an unharvested definition must be
        // able to expire while a harvested one is still held.
        let c: Cache<u32> = Cache::new(10, Duration::ZERO);
        c.insert("short".into(), 1, Duration::from_millis(1));
        c.insert("long".into(), 2, Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.get("short").is_none());
        assert_eq!(c.get("long").map(|(v, _)| v), Some(2));
    }

    #[test]
    fn an_expired_entry_is_kept_as_stale_for_the_grace_period() {
        let c: Cache<u32> = Cache::new(10, Duration::from_secs(60));
        c.insert("k".into(), 1, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(c.get("k"), None, "a stale entry was served as fresh");
        assert_eq!(c.get_stale("k"), Some(1));
    }

    #[test]
    fn a_fresh_entry_is_not_stale() {
        let c: Cache<u32> = Cache::new(10, Duration::from_secs(60));
        c.insert("k".into(), 1, Duration::from_secs(60));
        assert_eq!(c.get_stale("k"), None);
    }

    #[test]
    fn stale_entries_are_forgotten_after_the_grace_period() {
        let c: Cache<u32> = Cache::new(10, Duration::from_millis(1));
        c.insert("k".into(), 1, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(c.get_stale("k"), None);
    }

    #[test]
    fn a_promoted_stale_entry_is_stale_not_fresh() {
        let c: Cache<u32> = Cache::new(10, Duration::from_secs(60));
        c.insert_stale("k".into(), 1, Duration::from_secs(60));
        assert_eq!(c.get("k"), None);
        assert_eq!(c.get_stale("k"), Some(1));
    }

    #[test]
    fn stays_within_capacity() {
        let c: Cache<u32> = Cache::new(16, Duration::ZERO);
        for i in 0..200 {
            c.insert(format!("k{i}"), i, Duration::from_secs(60));
        }
        assert!(c.len() <= 16, "cache grew to {}", c.len());
    }
}
