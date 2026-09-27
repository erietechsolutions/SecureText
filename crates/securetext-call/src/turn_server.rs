//! A small TURN server (RFC 5766) for relaying call media, built on the
//! webrtc-rs `turn` crate. Used by the `securetext-turn` binary and by the
//! call tests. Operators who already run coturn can use that instead; the
//! app only needs a `turn:` address, a username and a password.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;

pub const REALM: &str = "securetext";

struct Users(Vec<(String, Vec<u8>)>);

impl AuthHandler for Users {
    fn auth_handle(&self, username: &str, _realm: &str, _src: SocketAddr) -> Result<Vec<u8>, turn::Error> {
        self.0
            .iter()
            .find(|(u, _)| u == username)
            .map(|(_, k)| k.clone())
            .ok_or(turn::Error::ErrFakeErr)
    }
}

pub struct TurnHandle {
    server: Server,
    pub listen: SocketAddr,
}

impl TurnHandle {
    pub async fn close(self) {
        let _ = self.server.close().await;
    }
}

/// Listen for TURN on `listen` (UDP). Relay allocations are opened on
/// `relay_ip` and announced as that address, so it must be reachable by
/// callers: the server's public IP in real use.
pub async fn start(listen: SocketAddr, relay_ip: IpAddr, users: &[(String, String)]) -> anyhow::Result<TurnHandle> {
    let conn = Arc::new(UdpSocket::bind(listen).await?);
    let listen = conn.local_addr()?;
    let bind_ip = if relay_ip.is_loopback() { relay_ip.to_string() } else { "0.0.0.0".to_string() };
    let server = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                relay_address: relay_ip,
                address: bind_ip,
                net: Arc::new(webrtc_util::vnet::net::Net::new(None)),
            }),
        }],
        realm: REALM.to_owned(),
        auth_handler: Arc::new(Users(
            users.iter().map(|(u, p)| (u.clone(), generate_auth_key(u, REALM, p))).collect(),
        )),
        channel_bind_timeout: std::time::Duration::from_secs(0),
        alloc_close_notify: None,
    })
    .await?;
    Ok(TurnHandle { server, listen })
}
