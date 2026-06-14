use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

/// In-memory, bidirectional map between real secrets and opaque sentinels.
/// Secrets are wiped from memory on drop. Never persisted.
pub struct Vault {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    by_secret: HashMap<String, String>,   // secret -> sentinel
    by_sentinel: HashMap<String, String>, // sentinel -> secret
    counter: u64,
}

impl Vault {
    /// Create an empty vault. Secrets are added lazily on first `sentinel_for` and
    /// wiped on drop.
    pub fn new() -> Self {
        Vault {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Lock the inner map, recovering the guard if a previous holder panicked
    /// while holding the lock. A poisoned mutex would otherwise make every later
    /// `lock().unwrap()` panic — turning one request's failure into a crash for
    /// all subsequent requests. The guarded data is a plain in-memory map with no
    /// cross-field invariant that a mid-operation panic could leave half-applied,
    /// so taking the inner guard is safe and keeps the proxy serving.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Return a stable sentinel for `secret`, registering it on first sight.
    /// Same secret -> same sentinel within this process.
    pub fn sentinel_for(&self, kind: &str, secret: &str) -> String {
        let mut g = self.lock();
        if let Some(s) = g.by_secret.get(secret) {
            return s.clone();
        }
        g.counter += 1;
        let sentinel = format!("«airlock:{}:{:04x}»", kind, g.counter);
        g.by_secret.insert(secret.to_string(), sentinel.clone());
        g.by_sentinel.insert(sentinel.clone(), secret.to_string());
        sentinel
    }

    /// Resolve a sentinel back to its secret, if known.
    pub fn secret_for(&self, sentinel: &str) -> Option<String> {
        self.lock().by_sentinel.get(sentinel).cloned()
    }

    /// Longest sentinel currently registered (for the M1 streaming look-back buffer).
    #[allow(dead_code)] // reserved for M1 streaming restore
    pub fn max_sentinel_len(&self) -> usize {
        self.lock()
            .by_sentinel
            .keys()
            .map(|k| k.len())
            .max()
            .unwrap_or(0)
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        let mut g = self.lock();
        for (mut k, mut v) in g.by_secret.drain() {
            k.zeroize();
            v.zeroize();
        }
        for (mut k, mut v) in g.by_sentinel.drain() {
            k.zeroize();
            v.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_secret_same_sentinel() {
        let v = Vault::new();
        let a = v.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        let b = v.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(a, b);
    }

    #[test]
    fn different_secrets_differ() {
        let v = Vault::new();
        let a = v.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        let b = v.sentinel_for("aws_key", "ASIAIOSFODNN7EXAMPLE");
        assert_ne!(a, b);
    }

    #[test]
    fn round_trips() {
        let v = Vault::new();
        let s = v.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(v.secret_for(&s).as_deref(), Some("AKIAIOSFODNN7EXAMPLE"));
    }

    /// A panic while another holder owns the lock poisons the mutex. The vault
    /// must keep serving (via the recovering `lock()` helper) so one request's
    /// failure can never crash every later request.
    #[test]
    fn recovers_from_a_poisoned_lock() {
        use std::sync::Arc;
        let v = Arc::new(Vault::new());
        let sentinel = v.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");

        // Poison the inner mutex: panic while holding the lock on another thread.
        let v2 = Arc::clone(&v);
        let poisoned = std::thread::spawn(move || {
            let _g = v2.inner.lock().unwrap();
            panic!("intentionally poison the vault mutex");
        })
        .join();
        assert!(poisoned.is_err(), "the helper thread should have panicked");

        // Despite the poison, reads and writes still work and stay consistent.
        assert_eq!(
            v.secret_for(&sentinel).as_deref(),
            Some("AKIAIOSFODNN7EXAMPLE")
        );
        assert_eq!(v.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE"), sentinel);
    }
}
