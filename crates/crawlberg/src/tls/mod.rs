//! TLS ClientHello fingerprint profiles for the reqwest HTTP path.
//!
//! Modern WAFs (Cloudflare, DataDome, Akamai) fingerprint the TLS handshake,
//! not just headers. The default `reqwest` stack emits a fixed, automation-like
//! ClientHello. [`TlsProfileProvider`] lets callers swap in a Chrome-like
//! profile (see [`ChromeLikeTlsProfile`], behind the `tls-stealth` feature)
//! without touching fetch logic. [`NoTlsSpoof`] (the default) is a no-op that
//! preserves the current behavior.

pub mod profile;
pub mod provider;

#[cfg(feature = "tls-stealth")]
pub use profile::ChromeLikeTlsProfile;
pub use profile::NoTlsSpoof;
pub use provider::{DynTlsProfileProvider, TlsProfileProvider};

/// Concrete client config type handed to `reqwest::Client::use_preconfigured_tls`.
///
/// Under `tls-stealth` this is `Arc<rustls::ClientConfig>`; otherwise it is an
/// opaque zero-sized type that is never constructed (the provider always
/// returns `None`).
#[cfg(feature = "tls-stealth")]
pub type TlsClientConfig = std::sync::Arc<rustls::ClientConfig>;

#[cfg(not(feature = "tls-stealth"))]
#[derive(Debug)]
pub struct TlsClientConfig;
