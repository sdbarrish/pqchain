//! Token-bucket rate limiting for peers, handshakes and RPC clients.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::Instant;

/// Refills `rate` tokens per second up to `burst`.
#[derive(Clone, Debug)]
pub struct Bucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}

impl Bucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Bucket { tokens: burst, last: Instant::now(), rate, burst }
    }

    /// Take `n` tokens if available.
    pub fn take(&mut self, n: f64) -> bool {
        self.take_at(n, Instant::now())
    }

    pub fn take_at(&mut self, n: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    fn is_full(&self, now: Instant) -> bool {
        self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * self.rate >= self.burst
    }
}

/// One bucket per key (e.g. client IP), with bounded memory.
pub struct Limiter<K> {
    buckets: Mutex<HashMap<K, Bucket>>,
    rate: f64,
    burst: f64,
    max_keys: usize,
}

impl<K: Hash + Eq + Clone> Limiter<K> {
    pub fn new(rate: f64, burst: f64, max_keys: usize) -> Self {
        Limiter { buckets: Mutex::new(HashMap::new()), rate, burst, max_keys }
    }

    pub fn take(&self, key: &K, n: f64) -> bool {
        let now = Instant::now();
        let mut m = self.buckets.lock().unwrap();
        if m.len() >= self.max_keys && !m.contains_key(key) {
            // Forget idle (full) buckets; if still full, refuse new keys.
            m.retain(|_, b| !b.is_full(now));
            if m.len() >= self.max_keys {
                return false;
            }
        }
        m.entry(key.clone()).or_insert_with(|| Bucket::new(self.rate, self.burst)).take_at(n, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_allows_burst_then_refills() {
        let t0 = Instant::now();
        let mut b = Bucket { tokens: 5.0, last: t0, rate: 10.0, burst: 5.0 };
        for _ in 0..5 {
            assert!(b.take_at(1.0, t0));
        }
        assert!(!b.take_at(1.0, t0), "burst exhausted");
        assert!(b.take_at(1.0, t0 + Duration::from_millis(100)), "refilled 1 token in 100 ms");
        assert!(!b.take_at(1.0, t0 + Duration::from_millis(100)));
        assert!(b.take_at(5.0, t0 + Duration::from_secs(10)), "never above burst, but refills to it");
        assert!(!b.take_at(1.0, t0 + Duration::from_secs(10)));
    }

    #[test]
    fn limiter_is_per_key_and_bounded() {
        let l = Limiter::new(0.0, 2.0, 2);
        assert!(l.take(&"a", 1.0) && l.take(&"a", 1.0) && !l.take(&"a", 1.0));
        assert!(l.take(&"b", 2.0), "other keys unaffected");
        assert!(!l.take(&"c", 1.0), "table full of non-idle keys: new keys refused");
    }
}
