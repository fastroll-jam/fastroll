use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Note: test-only
pub fn load_mock_certs_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certs = vec![cert.cert.into()];
    let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    (certs, key)
}
