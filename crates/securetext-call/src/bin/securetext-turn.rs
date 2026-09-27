//! `securetext-turn`: a TURN server for relaying SecureText call media.
//!
//! ```text
//! securetext-turn --public-ip 203.0.113.10 [--listen 0.0.0.0:3478] --user alice:long-random-password [--user ...]
//! ```
//!
//! Callers enter `turn:<public-ip>:3478` plus a username and password in
//! SecureText (Settings → Calls). The server relays encrypted media only:
//! it can see the IP addresses of the people using it, which is the
//! disclosed exposure of calls (threat-model.md), but not what they say.
//! Open UDP 3478 and the ephemeral UDP range for relays in the firewall.
//! Unlike the offline-delivery relay this is a clearnet service by nature;
//! run it somewhere that isn't linked to you if that matters.

use std::net::{IpAddr, SocketAddr};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut listen: SocketAddr = "0.0.0.0:3478".parse()?;
    let mut public_ip: Option<IpAddr> = None;
    let mut users = Vec::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().cloned().ok_or_else(|| anyhow::anyhow!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => listen = value()?.parse()?,
            "--public-ip" => public_ip = Some(value()?.parse()?),
            "--user" => {
                let v = value()?;
                let (u, p) = v.split_once(':').ok_or_else(|| anyhow::anyhow!("--user wants name:password"))?;
                anyhow::ensure!(p.len() >= 16, "use a password of at least 16 characters for {u}");
                users.push((u.to_string(), p.to_string()));
            }
            "--version" => {
                println!("securetext-turn {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => anyhow::bail!("unknown flag {other}; see the source header for usage"),
        }
    }
    let public_ip = public_ip.ok_or_else(|| anyhow::anyhow!("--public-ip is required"))?;
    anyhow::ensure!(!users.is_empty(), "at least one --user is required");
    let server = securetext_call::turn_server::start(listen, public_ip, &users).await?;
    eprintln!("[securetext-turn] relaying on {} as turn:{}:{}", server.listen, public_ip, server.listen.port());
    tokio::signal::ctrl_c().await?;
    server.close().await;
    Ok(())
}
