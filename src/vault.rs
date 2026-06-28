// SPDX-License-Identifier: LicenseRef-SUL-1.0
// Copyright (c) 2026 AK DevOps Solutions SL

use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

/// Initial capacity for the secret↔sentinel maps inside each `Vault`.
///
/// Pre-sizing matters for secret hygiene, not just speed: when a `HashMap` grows it
/// allocates a larger backing buffer and rehashes existing entries into it, leaving
/// the old buffer (still holding secret bytes) freed-but-unzeroed until the
/// allocator reuses it. `Drop` only zeroizes the *current* live entries, so each
/// reallocation can strand a copy of earlier secrets in deallocated memory. Most
/// requests touch fewer than 8 distinct secrets, so a capacity of 8 covers the
/// common case and avoids the reallocate-and-leak cycle for all but pathological
/// inputs.
const INITIAL_CAPACITY: usize = 8;

/// In-memory, bidirectional map between real secrets and opaque sentinels.
/// Secrets are wiped from memory on drop. Never persisted.
pub struct Vault {
    inner: Mutex<Inner>,
}

struct Inner {
    by_secret: HashMap<String, String>,   // secret -> sentinel
    by_sentinel: HashMap<String, String>, // sentinel -> secret
}

impl Vault {
    /// Create an empty vault. Secrets are added lazily on first `sentinel_for` and
    /// wiped on drop.
    ///
    /// The maps are pre-sized to [`INITIAL_CAPACITY`] so they don't reallocate (and
    /// strand un-zeroized secret bytes in freed buffers) for typical requests.
    pub fn new() -> Self {
        Vault {
            inner: Mutex::new(Inner {
                by_secret: HashMap::with_capacity(INITIAL_CAPACITY),
                by_sentinel: HashMap::with_capacity(INITIAL_CAPACITY),
            }),
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
    ///
    /// The tag is a 128-bit random value rendered as lowercase hex rather than a
    /// sequential counter. A predictable counter (`0001`, `0002`, …) is guessable:
    /// an attacker who can influence upstream text could craft a literal sentinel
    /// that round-trips to a real secret, and innocent user text could collide with
    /// a minted sentinel. A 128-bit random tag makes both forgery and accidental
    /// collision negligible. The dedup lookup runs FIRST so a repeated secret keeps
    /// its original sentinel (same secret -> same sentinel within the request).
    pub fn sentinel_for(&self, kind: &str, secret: &str) -> String {
        let mut g = self.lock();
        if let Some(s) = g.by_secret.get(secret) {
            return s.clone();
        }
        // 128 bits of randomness, lowercase hex (matches `mask::SENTINEL_RE`'s
        // `[0-9a-f]+` tag class). `rand::rng()` is the per-thread, auto-seeded CSPRNG.
        let mut tag = [0u8; 16];
        rand::rng().fill_bytes(&mut tag);
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        let sentinel = format!("«promtect:{kind}:{hex}»");
        g.by_secret.insert(secret.to_string(), sentinel.clone());
        g.by_sentinel.insert(sentinel.clone(), secret.to_string());
        sentinel
    }

    /// Resolve a sentinel back to its secret, if known.
    pub fn secret_for(&self, sentinel: &str) -> Option<String> {
        self.lock().by_sentinel.get(sentinel).cloned()
    }

    /// Whether `secret` was registered during request masking (one of the user's
    /// own secrets, which the restorer puts back into the response). The output
    /// scan uses this to ignore restored request secrets and flag only secrets the
    /// response itself introduced.
    pub fn knows_secret(&self, secret: &str) -> bool {
        self.lock().by_secret.contains_key(secret)
    }

    /// Longest sentinel currently registered. Bounds the streaming restorer's
    /// look-back buffer: a `«`-led run longer than this cannot be a sentinel.
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

    /// Distinct secrets must mint distinct sentinels, and the tags must NOT be the
    /// old guessable sequential counter (`0001`, `0002`, …). A forgeable sentinel
    /// would let crafted upstream text round-trip to a real secret, so the tag is a
    /// 128-bit random value; this asserts the two tags differ and are non-sequential.
    #[test]
    fn distinct_secrets_get_distinct_nonsequential_tags() {
        let v = Vault::new();
        let a = v.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        let b = v.sentinel_for("aws_key", "ASIAIOSFODNN7EXAMPLE");
        assert_ne!(a, b, "distinct secrets must not share a sentinel");

        let tag_a = tag_of(&a);
        let tag_b = tag_of(&b);
        // A random 128-bit tag is 32 lowercase hex chars; the old counter was 4.
        assert_eq!(
            tag_a.len(),
            32,
            "tag should be a 128-bit (32 hex char) value"
        );
        assert_eq!(
            tag_b.len(),
            32,
            "tag should be a 128-bit (32 hex char) value"
        );
        // Non-sequential: the second tag is not the first incremented, and neither
        // is the legacy `0001`/`0002` counter sentinel.
        assert_ne!(tag_a, tag_b, "two random tags should differ");
        assert_ne!(tag_a, "0001");
        assert_ne!(tag_b, "0002");
    }

    /// Minted sentinels must satisfy the `mask::SENTINEL_RE` grammar
    /// (`«promtect:[a-z0-9_]+:[0-9a-f]+»`) so the restorer recognises them. The
    /// random hex must be lowercase to match the `[0-9a-f]` class.
    #[test]
    fn sentinel_matches_grammar() {
        let v = Vault::new();
        let s = v.sentinel_for("s3_key", "AKIAIOSFODNN7EXAMPLE");
        let re = regex::Regex::new(r"^«promtect:[a-z0-9_]+:[0-9a-f]+»$")
            .expect("test sentinel grammar regex");
        assert!(
            re.is_match(&s),
            "sentinel {s:?} must match SENTINEL_RE grammar"
        );
    }

    /// Two fresh  instances must produce **different** sentinel tags for the
    /// same secret. Within a single vault the same secret always maps to the same
    /// sentinel (lookup-before-mint), but across vaults each tag is independently
    /// drawn from 128 bits of randomness, making a collision negligible.
    #[test]
    fn sentinel_tag_is_random_across_vaults() {
        let v1 = Vault::new();
        let v2 = Vault::new();
        let s1 = v1.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        let s2 = v2.sentinel_for("aws_key", "AKIAIOSFODNN7EXAMPLE");
        // Same secret, but each vault draws a fresh 128-bit random tag.
        assert_ne!(
            tag_of(&s1),
            tag_of(&s2),
            "two independent vaults must not share the same sentinel tag"
        );
    }

    /// Extract the hex tag segment from a `«promtect:KIND:TAG»` sentinel for tests.
    fn tag_of(sentinel: &str) -> &str {
        sentinel
            .trim_start_matches('«')
            .trim_end_matches('»')
            .rsplit(':')
            .next()
            .expect("sentinel always has a tag segment")
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
