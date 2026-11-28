//! Inference rate limit manager
//!
//! Manages token-based rate limiters, budgets, and cost calculators per route,
//! integrating with the request flow for inference endpoints.

use dashmap::DashMap;
use http::HeaderMap;
use std::sync::Arc;
use tracing::{debug, info, trace};

use zentinel_common::budget::{
    BudgetAlert, BudgetCheckResult, CostResult, InferenceLimitKey, MissingKeyAction,
};
use zentinel_config::{InferenceConfig, TokenEstimation};

use super::budget::TokenBudgetTracker;
use super::cost::CostCalculator;
use super::providers::create_provider;
use super::rate_limit::{TokenRateLimitResult, TokenRateLimiter};
use super::tokens::{TokenCounter, TokenEstimate, TokenSource};

/// Per-route inference state with rate limiter, budget, and cost tracking.
struct RouteInferenceState {
    /// Token rate limiter (per-minute)
    rate_limiter: Option<TokenRateLimiter>,
    /// Token budget tracker (per-period cumulative)
    budget_tracker: Option<TokenBudgetTracker>,
    /// Cost calculator
    cost_calculator: Option<CostCalculator>,
    /// Token counter (for estimation and actual counting)
    token_counter: TokenCounter,
    /// What the rate limiter counts a request against
    rate_limit_key: (InferenceLimitKey, MissingKeyAction),
    /// What the budget counts a request against
    budget_key: (InferenceLimitKey, MissingKeyAction),
    /// Route ID for logging
    route_id: String,
}

/// The keys a request is counted against by its route's token rate limit
/// and budget. The pre-check and the recording of the actual usage use the
/// same keys.
///
/// A key is the client key (the client address, an IPv6 client by its
/// network) or, for `key "header:<name>"`, `key:` followed by the first 16
/// hex digits of the SHA-256 of the header's value. The value itself (an API
/// key, say) is never kept, logged or used as a metric label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceKeys {
    /// The key of the token rate limiter
    pub rate_limit: String,
    /// The key of the token budget
    pub budget: String,
}

/// A request refused because it lacks the header its route's token rate
/// limit or budget is keyed by, under `missing-key "reject"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingInferenceKey {
    /// `rate-limit` or `budget`
    pub block: &'static str,
    /// The header (lowercase)
    pub header: String,
}

/// The key of one block (`block` names it), or the refusal of a request
/// without its header under `missing-key "reject"`.
fn limit_key(
    block: &'static str,
    (key, missing): &(InferenceLimitKey, MissingKeyAction),
    client_key: &str,
    headers: &HeaderMap,
) -> Result<String, MissingInferenceKey> {
    let InferenceLimitKey::Header(name) = key else {
        return Ok(client_key.to_string());
    };
    // The first value; an empty one is no key.
    let value = headers
        .get(name.as_str())
        .map(|value| value.as_bytes().trim_ascii())
        .filter(|value| !value.is_empty());
    match (value, missing) {
        (Some(value), _) => Ok(hashed_key(value)),
        (None, MissingKeyAction::ClientIp) => Ok(client_key.to_string()),
        (None, MissingKeyAction::Reject) => Err(MissingInferenceKey {
            block,
            header: name.clone(),
        }),
    }
}

/// `key:` and the first 16 hex digits of the SHA-256 of a header value.
/// The prefix keeps it apart from a client address.
pub fn hashed_key(value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value);
    format!("key:{}", hex::encode(&digest[..8]))
}

/// Manager for inference rate limiting, budgets, and cost tracking.
///
/// Each route with inference configuration gets its own TokenRateLimiter,
/// TokenBudgetTracker, and CostCalculator based on the route's configuration.
pub struct InferenceRateLimitManager {
    /// Per-route inference state (keyed by route ID)
    routes: DashMap<String, Arc<RouteInferenceState>>,
}

impl InferenceRateLimitManager {
    /// Create a new inference rate limit manager
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
        }
    }

    /// Register a route with inference configuration.
    ///
    /// Creates a TokenRateLimiter, TokenBudgetTracker, and CostCalculator
    /// as configured for the route.
    pub fn register_route(&self, route_id: &str, config: &InferenceConfig) {
        let provider = create_provider(&config.provider);

        // Determine estimation method (from rate_limit or default)
        let estimation_method = config
            .rate_limit
            .as_ref()
            .map(|rl| rl.estimation_method)
            .unwrap_or(TokenEstimation::Chars);

        let token_counter = TokenCounter::new(provider, estimation_method);

        // Create rate limiter if configured
        let rate_limiter = config.rate_limit.as_ref().map(|rl| {
            info!(
                route_id = route_id,
                tokens_per_minute = rl.tokens_per_minute,
                requests_per_minute = ?rl.requests_per_minute,
                burst_tokens = rl.burst_tokens,
                "Registered inference rate limiter"
            );
            TokenRateLimiter::new(rl.clone())
        });

        // Create budget tracker if configured
        let budget_tracker = config.budget.as_ref().map(|budget| {
            info!(
                route_id = route_id,
                period = ?budget.period,
                limit = budget.limit,
                enforce = budget.enforce,
                "Registered token budget tracker"
            );
            TokenBudgetTracker::new(budget.clone(), route_id)
        });

        // Create cost calculator if configured
        let cost_calculator = config.cost_attribution.as_ref().map(|cost| {
            info!(
                route_id = route_id,
                enabled = cost.enabled,
                pricing_rules = cost.pricing.len(),
                "Registered cost calculator"
            );
            CostCalculator::new(cost.clone(), route_id)
        });

        // Only register if at least one feature is enabled
        if rate_limiter.is_some() || budget_tracker.is_some() || cost_calculator.is_some() {
            let rate_limit_key = config
                .rate_limit
                .as_ref()
                .map(|rl| (rl.key.clone(), rl.missing_key))
                .unwrap_or_default();
            let budget_key = config
                .budget
                .as_ref()
                .map(|budget| (budget.key.clone(), budget.missing_key))
                .unwrap_or_default();
            let state = RouteInferenceState {
                rate_limiter,
                budget_tracker,
                cost_calculator,
                token_counter,
                rate_limit_key,
                budget_key,
                route_id: route_id.to_string(),
            };

            self.routes.insert(route_id.to_string(), Arc::new(state));

            info!(
                route_id = route_id,
                provider = ?config.provider,
                has_rate_limit = config.rate_limit.is_some(),
                has_budget = config.budget.is_some(),
                has_cost = config.cost_attribution.is_some(),
                "Registered inference route"
            );
        }
    }

    /// Check if a route has inference configuration registered.
    pub fn has_route(&self, route_id: &str) -> bool {
        self.routes.contains_key(route_id)
    }

    /// Check if a route has budget tracking enabled.
    pub fn has_budget(&self, route_id: &str) -> bool {
        self.routes
            .get(route_id)
            .map(|s| s.budget_tracker.is_some())
            .unwrap_or(false)
    }

    /// Check if a route has cost attribution enabled.
    pub fn has_cost_attribution(&self, route_id: &str) -> bool {
        self.routes
            .get(route_id)
            .map(|s| {
                s.cost_calculator
                    .as_ref()
                    .map(|c| c.is_enabled())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// The keys a request is counted against by the route's token rate limit
    /// and budget, from its client key (the client address, an IPv6 client
    /// by its network) and its headers.
    ///
    /// Returns `Err` for a request without the header a block is keyed by
    /// under `missing-key "reject"` (the rate limit is looked at first), and
    /// `None` for a route that is not registered.
    pub fn keys(
        &self,
        route_id: &str,
        client_key: &str,
        headers: &HeaderMap,
    ) -> Option<Result<InferenceKeys, MissingInferenceKey>> {
        let state = self.routes.get(route_id)?;
        let keys = || -> Result<InferenceKeys, MissingInferenceKey> {
            let rate_limit = match state.rate_limiter {
                Some(_) => limit_key("rate-limit", &state.rate_limit_key, client_key, headers)?,
                None => client_key.to_string(),
            };
            let budget = match state.budget_tracker {
                Some(_) => limit_key("budget", &state.budget_key, client_key, headers)?,
                None => client_key.to_string(),
            };
            Ok(InferenceKeys { rate_limit, budget })
        };
        Some(keys())
    }

    /// Check rate limit for a request.
    ///
    /// Returns the rate limit result and the estimated token count.
    pub fn check(
        &self,
        route_id: &str,
        key: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<InferenceCheckResult> {
        let state = self.routes.get(route_id)?;

        // Estimate tokens for the request
        let estimate = state.token_counter.estimate_request(headers, body);

        trace!(
            route_id = route_id,
            key = key,
            estimated_tokens = estimate.tokens,
            model = ?estimate.model,
            "Checking inference rate limit"
        );

        // Check rate limit if configured
        let rate_limit_result = if let Some(ref rate_limiter) = state.rate_limiter {
            rate_limiter.check(key, estimate.tokens)
        } else {
            TokenRateLimitResult::Allowed
        };

        Some(InferenceCheckResult {
            result: rate_limit_result,
            estimated_tokens: estimate.tokens,
            model: estimate.model,
        })
    }

    /// Check budget for a request.
    ///
    /// Returns the budget check result, or None if no budget is configured.
    pub fn check_budget(
        &self,
        route_id: &str,
        tenant: &str,
        estimated_tokens: u64,
    ) -> Option<BudgetCheckResult> {
        let state = self.routes.get(route_id)?;
        let budget_tracker = state.budget_tracker.as_ref()?;

        Some(budget_tracker.check(tenant, estimated_tokens))
    }

    /// Record budget usage after a request completes.
    ///
    /// Returns any budget alerts that were triggered.
    pub fn record_budget(
        &self,
        route_id: &str,
        tenant: &str,
        actual_tokens: u64,
    ) -> Vec<BudgetAlert> {
        if let Some(state) = self.routes.get(route_id) {
            if let Some(ref budget_tracker) = state.budget_tracker {
                return budget_tracker.record(tenant, actual_tokens);
            }
        }
        Vec::new()
    }

    /// Get budget status for a tenant.
    pub fn budget_status(
        &self,
        route_id: &str,
        tenant: &str,
    ) -> Option<zentinel_common::budget::TenantBudgetStatus> {
        let state = self.routes.get(route_id)?;
        let budget_tracker = state.budget_tracker.as_ref()?;
        Some(budget_tracker.status(tenant))
    }

    /// Calculate cost for a request.
    ///
    /// Returns the cost result, or None if cost attribution is not configured.
    pub fn calculate_cost(
        &self,
        route_id: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Option<CostResult> {
        let state = self.routes.get(route_id)?;
        let cost_calculator = state.cost_calculator.as_ref()?;

        if !cost_calculator.is_enabled() {
            return None;
        }

        Some(cost_calculator.calculate(model, input_tokens, output_tokens))
    }

    /// Record actual token usage from response.
    ///
    /// This adjusts the rate limiter based on actual vs estimated usage.
    pub fn record_actual(
        &self,
        route_id: &str,
        key: &str,
        headers: &HeaderMap,
        body: &[u8],
        estimated_tokens: u64,
    ) -> Option<TokenEstimate> {
        let state = self.routes.get(route_id)?;

        // Get actual token count from response
        let actual = state.token_counter.tokens_from_response(headers, body);

        // Only record if we got actual tokens
        if actual.tokens > 0 && actual.source != TokenSource::Estimated {
            // Update rate limiter if configured
            if let Some(ref rate_limiter) = state.rate_limiter {
                rate_limiter.record_actual(key, actual.tokens, estimated_tokens);
            }

            debug!(
                route_id = route_id,
                key = key,
                actual_tokens = actual.tokens,
                estimated_tokens = estimated_tokens,
                source = ?actual.source,
                "Recorded actual token usage"
            );
        }

        Some(actual)
    }

    /// Get the number of registered routes
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Get stats for a route.
    pub fn route_stats(&self, route_id: &str) -> Option<InferenceRouteStats> {
        let state = self.routes.get(route_id)?;

        // Get rate limit stats if available
        let (active_keys, tokens_per_minute, requests_per_minute) =
            if let Some(ref rate_limiter) = state.rate_limiter {
                let stats = rate_limiter.stats();
                (
                    stats.active_keys,
                    stats.tokens_per_minute,
                    stats.requests_per_minute,
                )
            } else {
                (0, 0, None)
            };

        Some(InferenceRouteStats {
            route_id: route_id.to_string(),
            active_keys,
            tokens_per_minute,
            requests_per_minute,
            has_budget: state.budget_tracker.is_some(),
            has_cost_attribution: state
                .cost_calculator
                .as_ref()
                .map(|c| c.is_enabled())
                .unwrap_or(false),
        })
    }

    /// Drop the rate limit buckets of idle clients on every route (called
    /// periodically). Returns how many were dropped.
    pub fn cleanup(&self) -> usize {
        let removed: usize = self
            .routes
            .iter()
            .filter_map(|state| state.rate_limiter.as_ref().map(|l| l.remove_idle()))
            .sum();
        trace!(removed, "Inference rate limit cleanup");
        removed
    }
}

impl Default for InferenceRateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of an inference rate limit check
#[derive(Debug)]
pub struct InferenceCheckResult {
    /// Rate limit decision
    pub result: TokenRateLimitResult,
    /// Estimated tokens for this request
    pub estimated_tokens: u64,
    /// Model name if detected
    pub model: Option<String>,
}

impl InferenceCheckResult {
    /// Returns true if the request is allowed
    pub fn is_allowed(&self) -> bool {
        self.result.is_allowed()
    }

    /// Get retry-after value in milliseconds (0 if allowed)
    pub fn retry_after_ms(&self) -> u64 {
        self.result.retry_after_ms()
    }
}

/// Stats for a route's inference configuration.
#[derive(Debug, Clone)]
pub struct InferenceRouteStats {
    /// Route ID
    pub route_id: String,
    /// Number of active rate limit keys
    pub active_keys: usize,
    /// Configured tokens per minute (0 if no rate limiting)
    pub tokens_per_minute: u64,
    /// Configured requests per minute (if any)
    pub requests_per_minute: Option<u64>,
    /// Whether budget tracking is enabled
    pub has_budget: bool,
    /// Whether cost attribution is enabled
    pub has_cost_attribution: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::{InferenceProvider, TokenRateLimit};

    fn test_inference_config() -> InferenceConfig {
        InferenceConfig {
            provider: InferenceProvider::OpenAi,
            model_header: None,
            rate_limit: Some(TokenRateLimit {
                tokens_per_minute: 10000,
                requests_per_minute: Some(100),
                burst_tokens: 2000,
                estimation_method: TokenEstimation::Chars,
                key: Default::default(),
                missing_key: Default::default(),
            }),
            budget: None,
            cost_attribution: None,
            routing: None,
            model_routing: None,
            guardrails: None,
        }
    }

    #[test]
    fn test_register_route() {
        let manager = InferenceRateLimitManager::new();
        manager.register_route("test-route", &test_inference_config());

        assert!(manager.has_route("test-route"));
        assert!(!manager.has_route("other-route"));
    }

    #[test]
    fn test_check_rate_limit() {
        let manager = InferenceRateLimitManager::new();
        manager.register_route("test-route", &test_inference_config());

        let headers = HeaderMap::new();
        let body = br#"{"messages": [{"content": "Hello world"}]}"#;

        let result = manager.check("test-route", "client-1", &headers, body);
        assert!(result.is_some());

        let check = result.unwrap();
        assert!(check.is_allowed());
        assert!(check.estimated_tokens > 0);
    }

    #[test]
    fn test_no_rate_limit_config() {
        let manager = InferenceRateLimitManager::new();

        // Config without any features should not register
        let config = InferenceConfig {
            provider: InferenceProvider::OpenAi,
            model_header: None,
            rate_limit: None,
            budget: None,
            cost_attribution: None,
            routing: None,
            model_routing: None,
            guardrails: None,
        };
        manager.register_route("no-limit-route", &config);

        assert!(!manager.has_route("no-limit-route"));
    }

    #[test]
    fn test_budget_only_config() {
        use zentinel_common::budget::{BudgetPeriod, TokenBudgetConfig};

        let manager = InferenceRateLimitManager::new();

        let config = InferenceConfig {
            provider: InferenceProvider::OpenAi,
            model_header: None,
            rate_limit: None,
            budget: Some(TokenBudgetConfig {
                period: BudgetPeriod::Daily,
                limit: 100000,
                alert_thresholds: vec![0.80, 0.90],
                enforce: true,
                rollover: false,
                burst_allowance: None,
                max_tenants: 10_000,
                key: Default::default(),
                missing_key: Default::default(),
            }),
            cost_attribution: None,
            routing: None,
            model_routing: None,
            guardrails: None,
        };
        manager.register_route("budget-route", &config);

        assert!(manager.has_route("budget-route"));
        assert!(manager.has_budget("budget-route"));
        assert!(!manager.has_cost_attribution("budget-route"));
    }

    /// A route keyed by `x-api-key` for the rate limit and by `x-org-id`
    /// for the budget, with the given `missing-key` for both.
    fn keyed_manager(missing: MissingKeyAction) -> InferenceRateLimitManager {
        let mut config = test_inference_config();
        if let Some(rate_limit) = config.rate_limit.as_mut() {
            rate_limit.key = InferenceLimitKey::Header("x-api-key".into());
            rate_limit.missing_key = missing;
        }
        config.budget = Some(zentinel_common::budget::TokenBudgetConfig {
            key: InferenceLimitKey::Header("x-org-id".into()),
            missing_key: missing,
            ..Default::default()
        });
        let manager = InferenceRateLimitManager::new();
        manager.register_route("keyed", &config);
        manager
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn keys_default_to_the_client_key() {
        let manager = InferenceRateLimitManager::new();
        manager.register_route("r", &test_inference_config());
        let keys = manager
            .keys("r", "10.0.0.1", &headers(&[("x-api-key", "secret")]))
            .unwrap()
            .unwrap();
        assert_eq!(keys.rate_limit, "10.0.0.1");
        assert_eq!(keys.budget, "10.0.0.1");
        assert!(manager
            .keys("other", "10.0.0.1", &HeaderMap::new())
            .is_none());
    }

    #[test]
    fn header_keys_are_hashed_per_block() {
        let manager = keyed_manager(MissingKeyAction::ClientIp);
        let keys = manager
            .keys(
                "keyed",
                "10.0.0.1",
                &headers(&[("x-api-key", "sk-secret-1"), ("x-org-id", "acme")]),
            )
            .unwrap()
            .unwrap();
        assert_eq!(keys.rate_limit, hashed_key(b"sk-secret-1"));
        assert_eq!(keys.budget, hashed_key(b"acme"));
        assert!(!keys.rate_limit.contains("secret"));
        assert_eq!(keys.rate_limit.len(), "key:".len() + 16);
        // The same key from another address is the same key; another key is
        // another.
        let again = manager
            .keys(
                "keyed",
                "10.0.0.2",
                &headers(&[("x-api-key", "sk-secret-1")]),
            )
            .unwrap()
            .unwrap();
        assert_eq!(again.rate_limit, keys.rate_limit);
        let other = manager
            .keys(
                "keyed",
                "10.0.0.1",
                &headers(&[("x-api-key", "sk-secret-2")]),
            )
            .unwrap()
            .unwrap();
        assert_ne!(other.rate_limit, keys.rate_limit);
    }

    #[test]
    fn the_first_header_value_is_the_key_and_an_empty_one_is_missing() {
        let manager = keyed_manager(MissingKeyAction::ClientIp);
        let keys = manager
            .keys(
                "keyed",
                "10.0.0.1",
                &headers(&[("x-api-key", "first"), ("x-api-key", "second")]),
            )
            .unwrap()
            .unwrap();
        assert_eq!(keys.rate_limit, hashed_key(b"first"));
        let keys = manager
            .keys("keyed", "10.0.0.1", &headers(&[("x-api-key", "")]))
            .unwrap()
            .unwrap();
        assert_eq!(keys.rate_limit, "10.0.0.1");
        // Without `x-org-id` the budget falls back to the client.
        assert_eq!(keys.budget, "10.0.0.1");
    }

    #[test]
    fn a_missing_key_is_refused_with_reject() {
        let manager = keyed_manager(MissingKeyAction::Reject);
        let refused = manager
            .keys("keyed", "10.0.0.1", &headers(&[("x-org-id", "acme")]))
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refused,
            MissingInferenceKey {
                block: "rate-limit",
                header: "x-api-key".into()
            }
        );
        let refused = manager
            .keys(
                "keyed",
                "10.0.0.1",
                &headers(&[("x-api-key", "k"), ("x-org-id", " ")]),
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.block, "budget");
    }
}
