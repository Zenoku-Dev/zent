// tls.rs — TLS (rustls/ring): загрузка PEM-сертификата, acceptor для STARTTLS
// и implicit-TLS слушателей (465/993/995).
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
pub use tokio_rustls::TlsAcceptor;

pub fn load_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, String> {
    let certs: Vec<CertificateDer> = {
        let mut rd = std::io::BufReader::new(
            std::fs::File::open(cert).map_err(|e| format!("open {}: {e}", cert.display()))?,
        );
        rustls_pemfile::certs(&mut rd)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse certs: {e}"))?
    };
    if certs.is_empty() {
        return Err(format!("no certificates in {}", cert.display()));
    }
    let key_der: PrivateKeyDer = {
        let mut rd = std::io::BufReader::new(
            std::fs::File::open(key).map_err(|e| format!("open {}: {e}", key.display()))?,
        );
        rustls_pemfile::private_key(&mut rd)
            .map_err(|e| format!("parse key: {e}"))?
            .ok_or_else(|| format!("no private key in {}", key.display()))?
    };
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| format!("bad cert/key pair: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}
