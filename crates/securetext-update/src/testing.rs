//! A local stand-in for GitHub Releases, for tests (this crate's and the
//! app's): one TLS server with a throwaway certificate, answering request
//! paths from a fixed table, reached through a [`Connector`] that routes
//! every host name to it the way Tor would route to the real hosts.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::https::{github_hosts, Connector, HttpsClient, Io};

/// Routes every "host" to one local TLS server, standing in for Tor.
pub struct Local(pub std::net::SocketAddr);

impl Connector for Local {
    fn connect<'a>(&'a self, _host: &'a str, _port: u16) -> BoxFuture<'a, std::io::Result<Box<dyn Io>>> {
        Box::pin(async move { Ok(Box::new(tokio::net::TcpStream::connect(self.0).await?) as Box<dyn Io>) })
    }
}

/// A TLS server answering each request path from a fixed table of raw
/// HTTP responses, with a certificate for the given names.
pub async fn server(names: &[&str], routes: Vec<(String, Vec<u8>)>) -> (std::net::SocketAddr, rustls::RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(routes);
    // Routes are matched on the request path only.
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let routes = routes.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let mut reader = BufReader::new(tls);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).await.unwrap();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).await.unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or("").to_string();
                let response = routes
                    .iter()
                    .find(|(p, _)| *p == path)
                    .map(|(_, r)| r.clone())
                    .unwrap_or_else(|| b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec());
                let mut tls = reader.into_inner();
                tls.write_all(&response).await.unwrap();
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, roots)
}

pub fn client(addr: std::net::SocketAddr, roots: rustls::RootCertStore) -> HttpsClient {
    HttpsClient::with_roots(Arc::new(Local(addr)), github_hosts(), Duration::from_secs(10), roots)
}

/// A `200 OK` response with `body`.
pub fn http_ok(body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    r.extend_from_slice(body);
    r
}
