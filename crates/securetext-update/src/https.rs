//! A deliberately small HTTPS GET client for update checks and downloads.
//!
//! It never opens a socket itself. Every connection comes from a
//! [`Connector`], which in the app is a Tor exit stream from the app's own
//! arti client (`securetext-net`), so update traffic can't reach the
//! clearnet by accident (roadmap Phase 6: a direct request to github.com
//! would reveal that this IP runs SecureText). Tests plug in a local TLS
//! server instead.
//!
//! Only what fetching a GitHub release needs is supported: `GET`, HTTP/1.1,
//! `Content-Length` or chunked bodies, and redirects between an allow-list
//! of hosts (github.com hands release downloads off to a CDN host). Size
//! caps apply to every response, so a hostile server can't make the app
//! buffer or write without limit.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// Opens a byte stream to `host:port`. The host name is passed through
/// unresolved: for Tor, the exit relay resolves it, so no DNS query leaves
/// this machine either.
pub trait Connector: Send + Sync + 'static {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, io::Result<Box<dyn Io>>>;
}

const MAX_REDIRECTS: usize = 5;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const USER_AGENT: &str = "SecureText-Updater";

#[derive(Clone)]
pub struct HttpsClient {
    connector: Arc<dyn Connector>,
    tls: tokio_rustls::TlsConnector,
    /// Host names (exact, or a `.suffix`) a request or redirect may go to.
    allowed_hosts: Vec<String>,
    /// Per request, covering connect, TLS and the whole body.
    timeout: Duration,
}

/// Hosts a GitHub release download touches.
pub fn github_hosts() -> Vec<String> {
    vec![
        "github.com".into(),
        ".githubusercontent.com".into(),
    ]
}

impl HttpsClient {
    /// Trust the Mozilla root set bundled into the binary (so the result
    /// doesn't depend on, or leak through, the OS certificate store).
    pub fn new(connector: Arc<dyn Connector>, allowed_hosts: Vec<String>, timeout: Duration) -> Self {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        Self::with_roots(connector, allowed_hosts, timeout, roots)
    }

    pub fn with_roots(
        connector: Arc<dyn Connector>,
        allowed_hosts: Vec<String>,
        timeout: Duration,
        roots: rustls::RootCertStore,
    ) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            connector,
            tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
            allowed_hosts,
            timeout,
        }
    }

    /// GET `url` into memory, refusing bodies over `max_bytes`.
    pub async fn get(&self, url: &str, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
        let mut body = Vec::new();
        self.get_with(url, max_bytes, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        })
        .await?;
        Ok(body)
    }

    /// GET `url`, handing the body to `sink` in pieces as it arrives.
    pub async fn get_with(
        &self,
        url: &str,
        max_bytes: u64,
        mut sink: impl FnMut(&[u8]) -> io::Result<()> + Send,
    ) -> anyhow::Result<()> {
        let mut url = Url::parse(url)?;
        for _ in 0..=MAX_REDIRECTS {
            anyhow::ensure!(self.host_allowed(&url.host), "refusing to contact {}", url.host);
            let response = tokio::time::timeout(self.timeout, self.request(&url, max_bytes, &mut sink))
                .await
                .map_err(|_| anyhow::anyhow!("request to {} timed out", url.host))??;
            match response {
                Outcome::Done => return Ok(()),
                Outcome::Redirect(location) => url = url.join(&location)?,
            }
        }
        anyhow::bail!("too many redirects")
    }

    fn host_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowed_hosts.iter().any(|allowed| match allowed.strip_prefix('.') {
            Some(suffix) => host.ends_with(&format!(".{suffix}")),
            None => host == *allowed,
        })
    }

    async fn request(
        &self,
        url: &Url,
        max_bytes: u64,
        sink: &mut (impl FnMut(&[u8]) -> io::Result<()> + Send),
    ) -> anyhow::Result<Outcome> {
        let stream = self.connector.connect(&url.host, url.port).await?;
        let name = ServerName::try_from(url.host.clone())?;
        let mut tls = self.tls.connect(name, stream).await?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            url.path, url.host
        );
        tls.write_all(request.as_bytes()).await?;
        tls.flush().await?;

        let mut reader = BufReader::new(tls);
        let head = read_head(&mut reader).await?;
        if (300..400).contains(&head.status) {
            let location = head
                .header("location")
                .ok_or_else(|| anyhow::anyhow!("redirect without a location"))?;
            return Ok(Outcome::Redirect(location.to_string()));
        }
        anyhow::ensure!(head.status == 200, "{} answered HTTP {}", url.host, head.status);

        let chunked = head
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        if chunked {
            read_chunked(&mut reader, max_bytes, sink).await?;
        } else if let Some(len) = head.header("content-length") {
            let len: u64 = len.trim().parse()?;
            anyhow::ensure!(len <= max_bytes, "response of {len} bytes is over the {max_bytes}-byte limit");
            copy_exact(&mut reader, len, sink).await?;
        } else {
            copy_to_end(&mut reader, max_bytes, sink).await?;
        }
        Ok(Outcome::Done)
    }
}

enum Outcome {
    Done,
    Redirect(String),
}

struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

async fn read_head<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> anyhow::Result<Head> {
    let mut total = 0;
    let mut status_line = String::new();
    total += read_line(reader, &mut status_line, MAX_HEADER_BYTES).await?;
    let mut parts = status_line.split_whitespace();
    anyhow::ensure!(parts.next().is_some_and(|v| v.starts_with("HTTP/1.")), "not an HTTP/1.x response");
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("malformed status line"))?;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        total += read_line(reader, &mut line, MAX_HEADER_BYTES - total.min(MAX_HEADER_BYTES)).await?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Head { status, headers })
}

/// One CRLF-terminated line, at most `limit` bytes.
async fn read_line<R: AsyncRead + Unpin>(reader: &mut BufReader<R>, out: &mut String, limit: usize) -> anyhow::Result<usize> {
    let mut bytes = Vec::new();
    let n = (&mut *reader).take(limit as u64 + 1).read_until(b'\n', &mut bytes).await?;
    anyhow::ensure!(n > 0, "connection closed mid-response");
    anyhow::ensure!(n <= limit && bytes.ends_with(b"\n"), "response header too large");
    out.push_str(std::str::from_utf8(&bytes)?);
    Ok(n)
}

async fn copy_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut remaining: u64,
    sink: &mut (impl FnMut(&[u8]) -> io::Result<()> + Send),
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..want]).await?;
        anyhow::ensure!(n > 0, "connection closed before the body was complete");
        sink(&buf[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

async fn copy_to_end<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_bytes: u64,
    sink: &mut (impl FnMut(&[u8]) -> io::Result<()> + Send),
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) => n,
            // Many servers skip TLS close_notify on `Connection: close`.
            // Without a length there's no way to tell truncation apart, so
            // callers must check what they got (the updater checks hashes).
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(());
        }
        total += n as u64;
        anyhow::ensure!(total <= max_bytes, "response is over the {max_bytes}-byte limit");
        sink(&buf[..n])?;
    }
}

async fn read_chunked<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    max_bytes: u64,
    sink: &mut (impl FnMut(&[u8]) -> io::Result<()> + Send),
) -> anyhow::Result<()> {
    let mut total = 0u64;
    loop {
        let mut line = String::new();
        read_line(reader, &mut line, 1024).await?;
        let size_text = line.trim().split(';').next().unwrap_or("");
        let size = u64::from_str_radix(size_text, 16).map_err(|_| anyhow::anyhow!("malformed chunk size"))?;
        if size == 0 {
            // Trailers, then the final blank line.
            loop {
                let mut trailer = String::new();
                read_line(reader, &mut trailer, 8 * 1024).await?;
                if trailer.trim().is_empty() {
                    return Ok(());
                }
            }
        }
        total = total.saturating_add(size);
        anyhow::ensure!(total <= max_bytes, "response is over the {max_bytes}-byte limit");
        copy_exact(reader, size, sink).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        anyhow::ensure!(&crlf == b"\r\n", "malformed chunk terminator");
    }
}

/// `https://host[:port]/path` and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| anyhow::anyhow!("only https:// URLs are allowed: {url}"))?;
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        anyhow::ensure!(!authority.contains('@'), "credentials in URLs are not allowed");
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>()?),
            None => (authority, 443),
        };
        anyhow::ensure!(
            !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
            "invalid host in {url}"
        );
        let path = path.split('#').next().unwrap_or("/");
        let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
        anyhow::ensure!(
            path.bytes().all(|b| (0x21..0x7f).contains(&b)),
            "URL path must be printable ASCII"
        );
        Ok(Self { host: host.to_ascii_lowercase(), port, path })
    }

    /// Resolve a `Location` header against this URL.
    pub fn join(&self, location: &str) -> anyhow::Result<Self> {
        if location.starts_with("https://") {
            Self::parse(location)
        } else if location.starts_with('/') && !location.starts_with("//") {
            Self::parse(&format!("https://{}:{}{}", self.host, self.port, location))
        } else {
            anyhow::bail!("unsupported redirect target: {location}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_strictly() {
        assert_eq!(
            Url::parse("https://github.com/a/b/releases/latest/download/x.json").unwrap(),
            Url { host: "github.com".into(), port: 443, path: "/a/b/releases/latest/download/x.json".into() }
        );
        assert_eq!(Url::parse("https://Example.org:8443").unwrap().port, 8443);
        assert!(Url::parse("http://github.com/").is_err(), "plain http");
        assert!(Url::parse("https://user:pw@github.com/").is_err());
        assert!(Url::parse("https://git hub.com/").is_err());
        let base = Url::parse("https://github.com/a").unwrap();
        assert_eq!(base.join("/b?c=d").unwrap().path, "/b?c=d");
        assert_eq!(base.join("https://objects.githubusercontent.com/x").unwrap().host, "objects.githubusercontent.com");
        assert!(base.join("//evil.example/x").is_err());
        assert!(base.join("ftp://x").is_err());
    }

    use crate::testing::{client, server};

    #[tokio::test]
    async fn follows_a_github_style_redirect_and_decodes_both_body_framings() {
        let routes = vec![
            (
                "/o/r/releases/latest/download/m.json".into(),
                b"HTTP/1.1 302 Found\r\nLocation: https://objects.githubusercontent.com/blob/1\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ),
            ("/blob/1".into(), b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world".to_vec()),
            (
                "/chunked".into(),
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n".to_vec(),
            ),
        ];
        let (addr, roots) = server(&["github.com", "objects.githubusercontent.com"], routes).await;
        let c = client(addr, roots);
        assert_eq!(c.get("https://github.com/o/r/releases/latest/download/m.json", 1024).await.unwrap(), b"hello world");
        assert_eq!(c.get("https://github.com/chunked", 1024).await.unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn refuses_oversized_bodies_foreign_hosts_and_bad_certificates() {
        let routes = vec![
            ("/big".into(), b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world".to_vec()),
            ("/away".into(), b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/x\r\n\r\n".to_vec()),
            ("/missing".into(), b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ];
        let (addr, roots) = server(&["github.com"], routes).await;
        let c = client(addr, roots);
        assert!(c.get("https://github.com/big", 10).await.is_err(), "over the cap");
        let err = c.get("https://github.com/away", 1024).await.unwrap_err().to_string();
        assert!(err.contains("refusing to contact evil.example"), "{err}");
        assert!(c.get("https://evil.example/x", 1024).await.is_err());
        assert!(c.get("https://github.com/missing", 1024).await.is_err());

        // A certificate that doesn't chain to the trusted roots (what a
        // malicious exit relay would have to present) is rejected.
        let (other_addr, _other_roots) = server(&["github.com"], vec![]).await;
        let (_, wrong_roots) = server(&["github.com"], vec![]).await;
        let err = client(other_addr, wrong_roots).get("https://github.com/big", 1024).await.unwrap_err();
        assert!(format!("{err:#}").to_lowercase().contains("certificate"), "{err:#}");
    }
}
