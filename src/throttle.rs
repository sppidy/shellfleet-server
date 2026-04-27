//! Tiny per-key in-memory throttle. Used to slow down brute-force
//! attacks on:
//!   - `/api/auth/mfa/verify` (key: GitHub login from pending JWT)
//!   - `/api/device/approve`  (key: caller IP)
//!
//! After `MAX_FAILS` failed attempts within the rolling window, the key
//! is locked for `LOCK_SECS`. Each successful action clears the
//! counter for that key. State lives in a single `Mutex<HashMap<...>>`
//! attached to AppState — no Redis, no external dep.
//!
//! This is **not** a substitute for an edge rate limiter (Cloudflare
//! WAF, nginx limit_req, etc.) — it is a defence-in-depth that runs
//! even when the edge is bypassed (Tailscale, dev tunnel, direct VM
//! access). The CE budget for "extra deps" is zero, so this module
//! deliberately stays small.

use std::collections::HashMap;
use std::sync::Mutex;

/// How many fails before locking the key.
pub const MAX_FAILS: u32 = 10;
/// How long the lock lasts after `MAX_FAILS`.
pub const LOCK_SECS: i64 = 15 * 60;
/// Idle time after which a key's record is considered stale and gets
/// dropped (so the map doesn't grow unboundedly).
const RECORD_TTL_SECS: i64 = 24 * 3600;

#[derive(Debug, Default)]
struct Record {
    fails: u32,
    locked_until: i64,
    last_touched: i64,
}

#[derive(Default)]
pub struct Throttle {
    records: Mutex<HashMap<String, Record>>,
}

pub enum CheckResult {
    /// Caller is currently locked out — `retry_after_secs` until the
    /// next attempt is permitted.
    Locked { retry_after_secs: i64 },
    /// Caller may proceed. Call `record_failure` if the action fails
    /// or `record_success` if it succeeds.
    Ok,
}

impl Throttle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether `key` is currently allowed to attempt the
    /// guarded action. Garbage-collects stale records on the way.
    pub fn check(&self, key: &str, now: i64) -> CheckResult {
        let mut map = self.records.lock().unwrap();
        // Opportunistic GC. Cheap because `retain` is O(n) and n is
        // bounded by the number of distinct attackers in the last day.
        map.retain(|_, r| now - r.last_touched < RECORD_TTL_SECS);

        match map.get(key) {
            Some(r) if r.locked_until > now => CheckResult::Locked {
                retry_after_secs: r.locked_until - now,
            },
            _ => CheckResult::Ok,
        }
    }

    pub fn record_failure(&self, key: &str, now: i64) {
        let mut map = self.records.lock().unwrap();
        let r = map.entry(key.to_string()).or_default();
        r.fails = r.fails.saturating_add(1);
        r.last_touched = now;
        if r.fails >= MAX_FAILS {
            r.locked_until = now + LOCK_SECS;
        }
    }

    pub fn record_success(&self, key: &str) {
        let mut map = self.records.lock().unwrap();
        map.remove(key);
    }
}
