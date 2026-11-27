//! Token counting and estimation for inference requests
//!
//! Provides utilities for counting tokens from responses and estimating
//! tokens from requests for rate limiting purposes.

use http::HeaderMap;
use tracing::{debug, trace};
use zentinel_config::TokenEstimation;

use super::providers::InferenceProviderAdapter;

/// Token count estimate with metadata
#[derive(Debug, Clone)]
pub struct TokenEstimate {
    /// Estimated token count
    pub tokens: u64,
    /// Source of the estimate
    pub source: TokenSource,
    /// Model name if known
    pub model: Option<String>,
}

/// Source of token count information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// From response headers (most accurate)
    Header,
    /// From response body JSON (accurate)
    Body,
    /// Estimated from content (approximate)
    Estimated,
}

/// Token counter for a specific provider
pub struct TokenCounter {
    provider: Box<dyn InferenceProviderAdapter>,
    estimation_method: TokenEstimation,
}

impl TokenCounter {
    /// Create a new token counter for the given provider
    pub fn new(
        provider: Box<dyn InferenceProviderAdapter>,
        estimation_method: TokenEstimation,
    ) -> Self {
        Self {
            provider,
            estimation_method,
        }
    }

    /// Estimate tokens for an incoming request (before processing)
    pub fn estimate_request(&self, headers: &HeaderMap, body: &[u8]) -> TokenEstimate {
        // Try to extract model from request
        let model = self.provider.extract_model(headers, body);

        // Estimate based on body content
        let tokens = self
            .provider
            .estimate_request_tokens(body, self.estimation_method);

        trace!(
            provider = self.provider.name(),
            tokens = tokens,
            model = ?model,
            method = ?self.estimation_method,
            "Estimated request tokens"
        );

        TokenEstimate {
            tokens,
            source: TokenSource::Estimated,
            model,
        }
    }

    /// Get actual tokens from response (after processing)
    ///
    /// Uses headers first (preferred), then falls back to body parsing.
    pub fn tokens_from_response(&self, headers: &HeaderMap, body: &[u8]) -> TokenEstimate {
        // Try headers first (most accurate, no body parsing needed)
        if let Some(tokens) = self.provider.tokens_from_headers(headers) {
            debug!(
                provider = self.provider.name(),
                tokens = tokens,
                source = "header",
                "Got actual token count from response headers"
            );
            return TokenEstimate {
                tokens,
                source: TokenSource::Header,
                model: None,
            };
        }

        // Fall back to body parsing
        if let Some(tokens) = self.provider.tokens_from_body(body) {
            debug!(
                provider = self.provider.name(),
                tokens = tokens,
                source = "body",
                "Got actual token count from response body"
            );
            return TokenEstimate {
                tokens,
                source: TokenSource::Body,
                model: None,
            };
        }

        // If we can't get actual tokens, return 0 (estimation already done on request)
        trace!(
            provider = self.provider.name(),
            "Could not extract actual token count from response"
        );
        TokenEstimate {
            tokens: 0,
            source: TokenSource::Estimated,
            model: None,
        }
    }

    /// Get the provider name
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }
}

/// The input and output tokens a provider reports in a response body that is
/// not streamed: `usage.prompt_tokens` / `usage.completion_tokens` (OpenAI)
/// or `usage.input_tokens` / `usage.output_tokens` (Anthropic).
pub fn usage_from_body(body: &[u8]) -> Option<(u64, u64)> {
    if body.is_empty() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    let usage = json.get("usage")?;
    let count = |name: &str| usage.get(name).and_then(|n| n.as_u64());
    match (count("prompt_tokens"), count("completion_tokens")) {
        (None, None) => {}
        (input, output) => return Some((input.unwrap_or(0), output.unwrap_or(0))),
    }
    match (count("input_tokens"), count("output_tokens")) {
        (None, None) => None,
        (input, output) => Some((input.unwrap_or(0), output.unwrap_or(0))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::providers::create_provider;
    use zentinel_config::InferenceProvider;

    #[test]
    fn test_request_estimation() {
        let provider = create_provider(&InferenceProvider::OpenAi);
        let counter = TokenCounter::new(provider, TokenEstimation::Chars);

        let body =
            br#"{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello world"}]}"#;
        let headers = HeaderMap::new();

        let estimate = counter.estimate_request(&headers, body);
        assert!(estimate.tokens > 0);
        assert_eq!(estimate.source, TokenSource::Estimated);
        assert_eq!(estimate.model, Some("gpt-4".to_string()));
    }

    #[test]
    fn test_response_parsing() {
        let provider = create_provider(&InferenceProvider::OpenAi);
        let counter = TokenCounter::new(provider, TokenEstimation::Chars);

        let body = br#"{"usage": {"total_tokens": 150}}"#;
        let headers = HeaderMap::new();

        let estimate = counter.tokens_from_response(&headers, body);
        assert_eq!(estimate.tokens, 150);
        assert_eq!(estimate.source, TokenSource::Body);
    }

    #[test]
    fn usage_split_from_a_response_body() {
        let openai =
            br#"{"usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}"#;
        assert_eq!(usage_from_body(openai), Some((10, 5)));
        let anthropic = br#"{"usage": {"input_tokens": 7, "output_tokens": 3}}"#;
        assert_eq!(usage_from_body(anthropic), Some((7, 3)));
        assert_eq!(usage_from_body(br#"{"usage": {"total_tokens": 15}}"#), None);
        assert_eq!(usage_from_body(br#"{"choices": []}"#), None);
        assert_eq!(usage_from_body(b"not json"), None);
        assert_eq!(usage_from_body(b""), None);
    }
}
