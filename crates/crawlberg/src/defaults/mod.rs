//! Default trait implementations for crawlberg.

mod cache;
pub mod dispatch;
pub mod domain_state;
mod emitter;
mod filter;
mod frontier;
mod llm_extractor;
mod rate_limiter;
mod store;
mod strategy;

pub use cache::NoopCache;
pub use dispatch::{
    FixedBudget, SimpleRetryPolicy, UnlimitedBudget, compute_backoff_ms, default_retry_policy, unlimited_budget,
};
pub use domain_state::{EwmaDomainState, EwmaTracker, LearningRetryPolicy, in_memory_domain_state};
pub use emitter::NoopEmitter;
pub use filter::NoopFilter;
pub use frontier::InMemoryFrontier;
#[cfg(test)]
pub use rate_limiter::NoopRateLimiter;
pub use rate_limiter::PerDomainThrottle;
pub use store::NoopStore;
pub use strategy::{AdaptiveStrategy, BestFirstStrategy, BfsStrategy, DfsStrategy};

/// Default user-agent used when no explicit UA is configured.
///
/// A realistic Chrome UA avoids the `crawlberg/<version>` bot string that the
/// HTTP paths would otherwise send by default.
pub(crate) fn default_user_agent() -> &'static str {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
}

/// Chrome-faithful default request headers (client hints + accept language).
///
/// Applied on the HTTP paths so requests do not read as automation. Callers'
/// `custom_headers` and per-request headers override these. The set mirrors
/// what a modern Chrome sends on a top-level navigation.
pub(crate) fn default_browser_headers() -> std::collections::HashMap<String, String> {
    let mut h = std::collections::HashMap::new();
    h.insert(
        "accept".to_string(),
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string(),
    );
    h.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());
    h.insert(
        "sec-ch-ua".to_string(),
        "\"Chromium\";v=\"145\", \"Google Chrome\";v=\"145\", \"Not.A/Brand\";v=\"99\"".to_string(),
    );
    h.insert("sec-ch-ua-mobile".to_string(), "?0".to_string());
    h.insert("sec-ch-ua-platform".to_string(), "\"Linux\"".to_string());
    h.insert("sec-fetch-site".to_string(), "none".to_string());
    h.insert("sec-fetch-mode".to_string(), "navigate".to_string());
    h.insert("sec-fetch-dest".to_string(), "document".to_string());
    h.insert("upgrade-insecure-requests".to_string(), "1".to_string());
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_user_agent_is_not_the_bot_string() {
        let ua = default_user_agent();
        assert!(!ua.contains("crawlberg"), "default UA must not expose the crawler name");
        assert!(ua.contains("Chrome"), "default UA should read as a real browser");
    }

    #[test]
    fn default_browser_headers_are_chrome_faithful() {
        let h = default_browser_headers();
        assert_eq!(h.get("accept-language").map(|s| s.as_str()), Some("en-US,en;q=0.9"));
        assert!(h.contains_key("sec-ch-ua"), "missing sec-ch-ua client hint");
        assert!(h.contains_key("sec-ch-ua-platform"));
        assert_eq!(h.get("sec-fetch-site").map(|s| s.as_str()), Some("none"));
        assert_eq!(h.get("sec-fetch-mode").map(|s| s.as_str()), Some("navigate"));
        assert_eq!(h.get("sec-fetch-dest").map(|s| s.as_str()), Some("document"));
        assert!(!h.contains_key("user-agent"), "preset must not set UA; caller owns it");
    }
}
