//! Token cache + single-flight refresh in front of
//! `aqua_auth::client::authenticate`. Concurrent callers share one
//! in-flight refresh.
//!
//! The CAIP-122 handshake itself (challenge fetch, message signing,
//! session exchange) is owned by `aqua-rs-auth`. This module is purely
//! about caching the resulting bearer token and serialising concurrent
//! refresh attempts.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aqua_auth::client::authenticate;
use tokio::sync::{Mutex, Notify};
use tracing::debug;

use crate::error::ClientError;

/// 60 seconds. We treat a token as needing refresh if `now + REFRESH_LEAD_SECS`
/// is at or past `valid_until`. Keeps us from racing the server clock.
const REFRESH_LEAD_SECS: u64 = 60;

pub(crate) type SignFn =
    Arc<dyn Fn(&str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> + Send + Sync>;

#[derive(Clone)]
struct Cached {
    token: String,
    valid_until: u64,
}

pub(crate) struct AuthState {
    base_url: String,
    my_did: String,
    signer: SignFn,
    cached: Mutex<Option<Cached>>,
    refresh: Notify,
    in_flight: std::sync::atomic::AtomicBool,
}

impl AuthState {
    pub fn new(base_url: String, my_did: String, signer: SignFn) -> Self {
        Self {
            base_url,
            my_did,
            signer,
            cached: Mutex::new(None),
            refresh: Notify::new(),
            in_flight: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn my_did(&self) -> &str {
        &self.my_did
    }

    /// Returns a valid bearer token, refreshing if necessary. At most one
    /// refresh runs concurrently; other callers await the notification and
    /// pick up the new value from the cache.
    pub async fn ensure_token(&self, http: &reqwest::Client) -> Result<String, ClientError> {
        loop {
            {
                let guard = self.cached.lock().await;
                if let Some(c) = guard.as_ref() {
                    if !needs_refresh(c.valid_until) {
                        return Ok(c.token.clone());
                    }
                }
            }

            // Try to become the refresher. If we win the race, we run it;
            // if we lose, we wait for the notification and loop.
            let claimed = self
                .in_flight
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok();

            if !claimed {
                // Someone else is refreshing; wait for them to publish.
                self.refresh.notified().await;
                continue;
            }

            // We own the refresh. Ensure we always release the lock and notify
            // waiters, even on error.
            let result = self.run_refresh(http).await;
            self.in_flight
                .store(false, std::sync::atomic::Ordering::Release);
            self.refresh.notify_waiters();
            return result;
        }
    }

    async fn run_refresh(&self, http: &reqwest::Client) -> Result<String, ClientError> {
        debug!(did = %self.my_did, "refreshing aqua-timestamp session token");
        let signer = self.signer.clone();
        let session = authenticate(http, &self.base_url, &self.my_did, move |msg| {
            (signer)(msg)
        })
        .await
        .map_err(|e| ClientError::Auth(e.to_string()))?;

        let mut guard = self.cached.lock().await;
        *guard = Some(Cached {
            token: session.token.clone(),
            valid_until: session.valid_until,
        });
        Ok(session.token)
    }
}

fn needs_refresh(valid_until: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now + REFRESH_LEAD_SECS >= valid_until
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_refresh_when_close_to_expiry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(needs_refresh(now + 30));
        assert!(!needs_refresh(now + 3600));
    }
}
