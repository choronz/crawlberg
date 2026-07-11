//! Pluggable TLS fingerprint provider trait.

use std::sync::Arc;

use crate::tls::TlsClientConfig;

/// Provider that resolves to an optional preconfigured TLS client config.
///
/// Implementors return `None` to keep crawlberg's default TLS behavior, or
/// `Some(config)` to embed a custom [`rustls::ClientConfig`] (e.g. a Chrome-like
/// ClientHello) into the `reqwest` client via `use_preconfigured_tls`.
///
/// Mirrors the pluggable [`crate::ProxyProvider`] pattern: callers (or stealth
/// vendors) supply the implementation; the engine stays backend-agnostic.
pub trait TlsProfileProvider: Send + Sync + std::fmt::Debug {
    /// Return the client config to apply, or `None` for default behavior.
    fn client_config(&self) -> Option<TlsClientConfig>;
}

/// Type-erased TLS profile provider.
pub type DynTlsProfileProvider = Arc<dyn TlsProfileProvider>;
