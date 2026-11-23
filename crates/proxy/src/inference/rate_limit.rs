//! Token-based rate limiting for inference endpoints
//!
//! Provides dual-bucket rate limiting that tracks both:
//! - Tokens per minute (primary limit for LLM APIs)
//! - Requests per minute (secondary limit to prevent abuse)

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use zentinel_config::TokenRateLimit;

/// Result of a rate limit check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRateLimitResult {
    /// Request is allowed
    Allowed,
    /// Token limit exceeded
    TokensExceeded {
        /// Milliseconds until retry is allowed
        retry_after_ms: u64,
    },
    /// Request limit exceeded
    RequestsExceeded {
        /// Milliseconds until retry is allowed
        retry_after_ms: u64,
    },
}

impl TokenRateLimitResult {
    /// Returns true if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Get retry-after value in milliseconds (0 if allowed)
    pub fn retry_after_ms(&self) -> u64 {
        match self {
            Self::Allowed => 0,
            Self::TokensExceeded { retry_after_ms } => *retry_after_ms,
            Self::RequestsExceeded { retry_after_ms } => *retry_after_ms,
        }
    }
}

/// Token bucket for rate limiting
struct TokenBucket {
    /// Current token count
    tokens: AtomicU64,
    /// Maximum tokens (burst capacity)
    max_tokens: u64,
    /// Tokens added per millisecond
    refill_rate: f64,
    /// Last refill timestamp
    last_refill: std::sync::Mutex<Instant>,
}

impl TokenBucket {
    fn new(tokens_per_minute: u64, burst_tokens: u64) -> Self {
        // Calculate refill rate: tokens per millisecond
        let refill_rate = tokens_per_minute as f64 / 60_000.0;

        Self {
            tokens: AtomicU64::new(burst_tokens),
            max_tokens: burst_tokens,
            refill_rate,
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Try to consume tokens from the bucket
    fn try_consume(&self, amount: u64) -> Result<(), u64> {
        // First, refill based on elapsed time
        self.refill();

        // Try to consume
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < amount {
                // Not enough tokens - calculate wait time
                let needed = amount - current;
                let wait_ms = (needed as f64 / self.refill_rate).ceil() as u64;
                return Err(wait_ms);
            }

            // Try to atomically subtract
            if self
                .tokens
                .compare_exchange(
                    current,
                    current - amount,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Ok(());
            }
            // CAS failed, retry
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        if elapsed.as_millis() > 0 {
            let refill_amount = (elapsed.as_millis() as f64 * self.refill_rate) as u64;
            if refill_amount > 0 {
                let current = self.tokens.load(Ordering::Acquire);
                let new_tokens = (current + refill_amount).min(self.max_tokens);
                self.tokens.store(new_tokens, Ordering::Release);
                *last = now;
            }
        }
    }

    /// Get current token count
    fn current_tokens(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Acquire)
    }

    /// Whether the bucket has refilled to its capacity. Such a bucket is the
    /// same as a new one, so it can be dropped without changing any limit.
    fn is_full(&self) -> bool {
        self.current_tokens() >= self.max_tokens
    }
}

/// Most clients one inference rate limiter keeps a bucket for, per bucket
/// kind (tokens, requests).
pub(crate) const MAX_TRACKED_KEYS: usize = 100_000;

/// The bucket for `key`, created if missing.
///
/// A map at [`MAX_TRACKED_KEYS`] first drops its full buckets; if it is still
/// full, the request is checked against a new bucket that is not kept. A
/// client then still cannot take more than one burst in one request, but its
/// usage is not carried over until the map has room again.
fn bucket_for<'a>(
    buckets: &'a DashMap<String, TokenBucket>,
    key: &str,
    new_bucket: impl Fn() -> TokenBucket,
) -> BucketRef<'a> {
    if let Some(bucket) = buckets.get(key) {
        return BucketRef::Kept(bucket);
    }
    if buckets.len() >= MAX_TRACKED_KEYS {
        buckets.retain(|_, bucket| !bucket.is_full());
        if buckets.len() >= MAX_TRACKED_KEYS {
            trace!(key = key, "Inference rate limiter full; bucket not kept");
            return BucketRef::Transient(new_bucket());
        }
    }
    BucketRef::Kept(
        buckets
            .entry(key.to_string())
            .or_insert_with(new_bucket)
            .downgrade(),
    )
}

/// A bucket held in the map, or one made for a single check.
enum BucketRef<'a> {
    Kept(dashmap::mapref::one::Ref<'a, String, TokenBucket>),
    Transient(TokenBucket),
}

impl std::ops::Deref for BucketRef<'_> {
    type Target = TokenBucket;

    fn deref(&self) -> &TokenBucket {
        match self {
            BucketRef::Kept(bucket) => bucket,
            BucketRef::Transient(bucket) => bucket,
        }
    }
}

/// Token-based rate limiter for inference endpoints
///
/// Tracks rate limits per key (typically client IP or API key).
pub struct TokenRateLimiter {
    /// Token buckets per key
    token_buckets: DashMap<String, TokenBucket>,
    /// Request buckets per key (optional)
    request_buckets: Option<DashMap<String, TokenBucket>>,
    /// Configuration
    config: TokenRateLimit,
}

impl TokenRateLimiter {
    /// Create a new token rate limiter
    pub fn new(config: TokenRateLimit) -> Self {
        let request_buckets = config.requests_per_minute.map(|rpm| DashMap::new());

        Self {
            token_buckets: DashMap::new(),
            request_buckets,
            config,
        }
    }

    /// Check if a request is allowed
    ///
    /// Both token and request limits must pass for the request to be allowed.
    pub fn check(&self, key: &str, estimated_tokens: u64) -> TokenRateLimitResult {
        // Check token limit
        let token_bucket = bucket_for(&self.token_buckets, key, || {
            TokenBucket::new(self.config.tokens_per_minute, self.config.burst_tokens)
        });

        if let Err(retry_ms) = token_bucket.try_consume(estimated_tokens) {
            trace!(
                key = key,
                estimated_tokens = estimated_tokens,
                retry_after_ms = retry_ms,
                "Token rate limit exceeded"
            );
            return TokenRateLimitResult::TokensExceeded {
                retry_after_ms: retry_ms,
            };
        }

        // Check request limit if configured
        if let (Some(rpm), Some(ref request_buckets)) =
            (self.config.requests_per_minute, &self.request_buckets)
        {
            let request_bucket = bucket_for(request_buckets, key, || {
                // For request limiting, use burst = rpm / 6 (10 second burst)
                let burst = rpm.max(1) / 6;
                TokenBucket::new(rpm, burst.max(1))
            });

            if let Err(retry_ms) = request_bucket.try_consume(1) {
                trace!(
                    key = key,
                    retry_after_ms = retry_ms,
                    "Request rate limit exceeded"
                );
                return TokenRateLimitResult::RequestsExceeded {
                    retry_after_ms: retry_ms,
                };
            }
        }

        trace!(
            key = key,
            estimated_tokens = estimated_tokens,
            "Rate limit check passed"
        );
        TokenRateLimitResult::Allowed
    }

    /// Record actual token usage after response
    ///
    /// This allows adjusting the bucket based on actual vs estimated usage.
    /// If actual < estimated, refund the difference.
    /// If actual > estimated, consume the extra (best effort).
    pub fn record_actual(&self, key: &str, actual_tokens: u64, estimated_tokens: u64) {
        if let Some(bucket) = self.token_buckets.get(key) {
            if actual_tokens < estimated_tokens {
                // Refund over-estimation
                let refund = estimated_tokens - actual_tokens;
                let current = bucket.tokens.load(Ordering::Acquire);
                let new_tokens = (current + refund).min(bucket.max_tokens);
                bucket.tokens.store(new_tokens, Ordering::Release);

                debug!(
                    key = key,
                    actual = actual_tokens,
                    estimated = estimated_tokens,
                    refund = refund,
                    "Refunded over-estimated tokens"
                );
            } else if actual_tokens > estimated_tokens {
                // Under-estimation - try to consume extra (don't block)
                let extra = actual_tokens - estimated_tokens;
                let current = bucket.tokens.load(Ordering::Acquire);
                let to_consume = extra.min(current);
                if to_consume > 0 {
                    bucket.tokens.fetch_sub(to_consume, Ordering::AcqRel);
                }

                debug!(
                    key = key,
                    actual = actual_tokens,
                    estimated = estimated_tokens,
                    consumed_extra = to_consume,
                    "Consumed under-estimated tokens"
                );
            }
        }
    }

    /// Get current token count for a key
    pub fn current_tokens(&self, key: &str) -> Option<u64> {
        self.token_buckets.get(key).map(|b| b.current_tokens())
    }

    /// Drop the buckets that have refilled to capacity: those clients have
    /// been idle long enough that a new bucket behaves the same.
    pub fn remove_idle(&self) -> usize {
        let before = self.token_buckets.len();
        self.token_buckets.retain(|_, bucket| !bucket.is_full());
        let mut removed = before - self.token_buckets.len();
        if let Some(ref request_buckets) = self.request_buckets {
            let before = request_buckets.len();
            request_buckets.retain(|_, bucket| !bucket.is_full());
            removed += before - request_buckets.len();
        }
        removed
    }

    /// Get stats for metrics
    pub fn stats(&self) -> TokenRateLimiterStats {
        TokenRateLimiterStats {
            active_keys: self.token_buckets.len(),
            tokens_per_minute: self.config.tokens_per_minute,
            requests_per_minute: self.config.requests_per_minute,
        }
    }
}

/// Stats for the token rate limiter
#[derive(Debug, Clone)]
pub struct TokenRateLimiterStats {
    /// Number of active rate limit keys
    pub active_keys: usize,
    /// Configured tokens per minute
    pub tokens_per_minute: u64,
    /// Configured requests per minute (if any)
    pub requests_per_minute: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::TokenEstimation;

    fn test_config() -> TokenRateLimit {
        TokenRateLimit {
            tokens_per_minute: 1000,
            requests_per_minute: Some(10),
            burst_tokens: 200,
            estimation_method: TokenEstimation::Chars,
        }
    }

    /// One token a second, so a used bucket stays below its burst for the
    /// length of a test.
    fn slow_config() -> TokenRateLimit {
        TokenRateLimit {
            tokens_per_minute: 60,
            requests_per_minute: None,
            burst_tokens: 200,
            estimation_method: TokenEstimation::Chars,
        }
    }

    #[test]
    fn remove_idle_drops_full_buckets_only() {
        let limiter = TokenRateLimiter::new(slow_config());
        assert!(limiter.check("idle", 0).is_allowed());
        assert!(limiter.check("busy", 100).is_allowed());

        assert_eq!(limiter.remove_idle(), 1);
        assert_eq!(limiter.current_tokens("idle"), None);
        assert_eq!(limiter.current_tokens("busy"), Some(100));
    }

    #[test]
    fn buckets_stop_growing_at_the_limit() {
        let limiter = TokenRateLimiter::new(slow_config());
        for i in 0..MAX_TRACKED_KEYS {
            assert!(limiter.check(&format!("client-{i}"), 100).is_allowed());
        }
        assert_eq!(limiter.stats().active_keys, MAX_TRACKED_KEYS);

        // A new client is checked against a bucket that is not kept: one
        // request still cannot take more than a burst.
        assert!(limiter.check("new", 100).is_allowed());
        assert!(!limiter.check("new", 300).is_allowed());
        assert_eq!(limiter.stats().active_keys, MAX_TRACKED_KEYS);
        assert_eq!(limiter.current_tokens("new"), None);

        // Known clients keep their state.
        assert!(!limiter.check("client-0", 150).is_allowed());
    }

    #[test]
    fn full_map_drops_idle_buckets_to_make_room() {
        let limiter = TokenRateLimiter::new(slow_config());
        for i in 0..MAX_TRACKED_KEYS {
            assert!(limiter.check(&format!("client-{i}"), 0).is_allowed());
        }
        assert!(limiter.check("new", 100).is_allowed());
        assert_eq!(limiter.stats().active_keys, 1);
        assert_eq!(limiter.current_tokens("new"), Some(100));
    }

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = TokenRateLimiter::new(test_config());

        // First request should succeed
        let result = limiter.check("test-key", 50);
        assert!(result.is_allowed());

        // Should still have tokens
        let current = limiter.current_tokens("test-key").unwrap();
        assert!(current > 0);
    }

    #[test]
    fn test_token_exhaustion() {
        let limiter = TokenRateLimiter::new(test_config());

        // Exhaust tokens
        for _ in 0..4 {
            let _ = limiter.check("test-key", 50);
        }

        // This should exceed the 200 burst tokens
        let result = limiter.check("test-key", 50);
        assert!(!result.is_allowed());
        assert!(matches!(
            result,
            TokenRateLimitResult::TokensExceeded { .. }
        ));
    }

    #[test]
    fn test_actual_token_refund() {
        let limiter = TokenRateLimiter::new(test_config());

        // Consume with high estimate
        let _ = limiter.check("test-key", 100);
        let before = limiter.current_tokens("test-key").unwrap();

        // Record actual as lower
        limiter.record_actual("test-key", 50, 100);
        let after = limiter.current_tokens("test-key").unwrap();

        // Should have refunded 50 tokens
        assert!(after > before);
    }
}
