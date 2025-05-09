use crate::certs::{cert::load_mock_certs_and_key, dangerous_verifier::SkipServerVerification};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

pub const JAM_QUIC_ALPN: &[u8] = b"jamnp-s/0/03c6255f";

pub struct QuicEndpoint {
    inner: quinn::Endpoint,
}

impl QuicEndpoint {
    pub fn new(listen_addr: SocketAddrV6) -> Self {
        // Using dangerous certs
        let (certs, key) = load_mock_certs_and_key();
        Self {
            inner: Self::configure_endpoint(listen_addr, certs, key),
        }
    }

    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.inner
    }

    /// Configures a QUIC endpoint as a server, which can both initiate and accept connections.
    fn configure_endpoint(
        listen_addr: SocketAddrV6,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> quinn::Endpoint {
        let listen_addr = SocketAddr::new(IpAddr::V6(*listen_addr.ip()), listen_addr.port());
        let mut endpoint =
            quinn::Endpoint::server(Self::server_config(certs, key), listen_addr).unwrap();
        endpoint.set_default_client_config(Self::client_config());
        endpoint
    }

    fn server_config(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> quinn::ServerConfig {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .unwrap();
        server_crypto.alpn_protocols = vec![JAM_QUIC_ALPN.to_vec()];
        quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).unwrap(),
        ))
    }

    fn client_config() -> quinn::ClientConfig {
        // Insecure connection
        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![JAM_QUIC_ALPN.to_vec()];
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()))
    }
}
