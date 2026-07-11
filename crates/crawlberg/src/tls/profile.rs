//! Built-in TLS profile implementations.

use crate::tls::TlsClientConfig;
use crate::tls::TlsProfileProvider;

/// Default provider: applies no TLS spoofing, preserving current behavior.
///
/// Safe to use unconditionally (including when the `tls-stealth` feature is
/// off); it always returns `None`.
#[derive(Debug, Default)]
pub struct NoTlsSpoof;

impl TlsProfileProvider for NoTlsSpoof {
    fn client_config(&self) -> Option<TlsClientConfig> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tls_spoof_is_a_noop() {
        assert!(NoTlsSpoof.client_config().is_none());
    }

    #[cfg(feature = "tls-stealth")]
    #[test]
    fn chrome_profile_yields_a_chrome_like_config() {
        let cfg = ChromeLikeTlsProfile
            .client_config()
            .expect("chrome profile must produce a config");
        assert!(cfg.alpn_protocols.iter().any(|p| p == b"h2"), "missing h2 ALPN");
        assert!(
            cfg.alpn_protocols.iter().any(|p| p == b"http/1.1"),
            "missing http/1.1 ALPN"
        );
        assert!(cfg.enable_early_data, "early data should be enabled");
    }
}

/// Chrome-like ClientHello profile. Only available with the `tls-stealth`
/// feature (which switches `reqwest` to a rustls backend).
#[cfg(feature = "tls-stealth")]
pub use chrome::ChromeLikeTlsProfile;

#[cfg(feature = "tls-stealth")]
mod chrome {
    use std::sync::Arc;

    use rustls::RootCertStore;

    use crate::tls::TlsClientConfig;
    use crate::tls::TlsProfileProvider;

    /// Mimics a modern Chrome (>= 120) TLS ClientHello: ALPN `h2,http/1.1` and
    /// TLS 1.2/1.3 with 0-RTT early data.
    ///
    /// This defeats shallow JA3 allow/deny lists and brings the handshake in
    /// line with a real browser. It is *not* a perfect BoringSSL clone — deep
    /// JA3N / Akamai-hash parity (exact cipher-suite ordering, GREASE) would
    /// require a uTLS-style backend, which a future optional provider can
    /// supply behind the same trait.
    #[derive(Debug, Default)]
    pub struct ChromeLikeTlsProfile;

    impl TlsProfileProvider for ChromeLikeTlsProfile {
        fn client_config(&self) -> Option<TlsClientConfig> {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            // Pick the `ring` provider explicitly: reqwest's `rustls` feature
            // also pulls in `aws-lc-rs`, so the auto-selected default would be
            // ambiguous at runtime. An explicit provider avoids that.
            let provider = rustls::crypto::ring::default_provider();
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .ok()?
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let mut config = config;
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            config.enable_early_data = true;
            Some(Arc::new(config))
        }
    }
}
