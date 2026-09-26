//! Talking to a relay over an already-dialed stream (the caller does the
//! Tor dial, so this works over any transport).

use securetext_net::{MuxMode, SecureMux};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{read_json, write_json, Request, Response, MAX_RESPONSE_FRAME};

/// Run `requests` in order over one connection and return the responses.
///
/// The client's Noise static key is generated fresh for every call. Using
/// the identity's long-term Noise key here would hand the relay a stable
/// identifier linking every deposit and collection a user makes.
pub async fn exchange<S>(mut stream: S, relay_noise_public: &[u8], requests: Vec<Request>) -> anyhow::Result<Vec<Response>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let throwaway = snow::Builder::new(securetext_net::NOISE_PATTERN.parse()?)
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("noise keygen: {e:?}"))?;
    let (noise, relay_key) = securetext_net::handshake_initiator(&mut stream, &throwaway.private).await?;
    anyhow::ensure!(
        relay_key == relay_noise_public,
        "relay presented an unexpected key; refusing to use it"
    );
    let mut mux = SecureMux::new(stream, noise, MuxMode::Client);
    let mut s = mux.open().await?;
    let mut responses = Vec::with_capacity(requests.len());
    for request in requests {
        write_json(&mut s, &request).await?;
        let response: Response = read_json(&mut s, MAX_RESPONSE_FRAME)
            .await?
            .ok_or_else(|| anyhow::anyhow!("relay closed the connection"))?;
        responses.push(response);
    }
    drop(s);
    let _ = mux.close().await;
    Ok(responses)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{mailbox_id, server::serve_connection, Limits, RelayStore, StoredBlob};

    fn relay_keys() -> snow::Keypair {
        snow::Builder::new(securetext_net::NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap()
    }

    fn spawn_relay(keys: &snow::Keypair) -> (Arc<Mutex<RelayStore>>, impl Fn() -> tokio::io::DuplexStream) {
        let store = Arc::new(Mutex::new(RelayStore::in_memory(Limits::default()).unwrap()));
        let private = keys.private.clone();
        let for_dial = store.clone();
        let dial = move || {
            let (client, server) = tokio::io::duplex(1 << 20);
            let store = for_dial.clone();
            let private = private.clone();
            tokio::spawn(async move {
                let _ = serve_connection(server, &private, store).await;
            });
            client
        };
        (store, dial)
    }

    #[tokio::test]
    async fn deposit_then_collect_over_noise() {
        let keys = relay_keys();
        let (_store, dial) = spawn_relay(&keys);
        let secret = vec![5u8; 32];
        let mailbox = mailbox_id(&secret);

        let r = exchange(dial(), &keys.public, vec![Request::Deposit { mailbox: mailbox.clone(), blob: b"sealed".to_vec() }])
            .await
            .unwrap();
        assert_eq!(r, vec![Response::Deposited]);

        // Fetch and ack on one connection.
        let r = exchange(dial(), &keys.public, vec![Request::Fetch { secret: secret.clone(), limit: 10 }])
            .await
            .unwrap();
        let Response::Blobs { items } = &r[0] else { panic!("expected blobs, got {r:?}") };
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].blob, b"sealed");
        let ids = items.iter().map(|b: &StoredBlob| b.id).collect();
        let r = exchange(
            dial(),
            &keys.public,
            vec![Request::Ack { secret: secret.clone(), ids }, Request::Fetch { secret, limit: 10 }],
        )
        .await
        .unwrap();
        assert_eq!(r, vec![Response::Acked { removed: 1 }, Response::Blobs { items: vec![] }]);
    }

    #[tokio::test]
    async fn a_relay_with_the_wrong_key_is_refused() {
        let keys = relay_keys();
        let (_store, dial) = spawn_relay(&keys);
        let expected = relay_keys().public; // a different relay's key
        let err = exchange(dial(), &expected, vec![Request::Fetch { secret: vec![1; 32], limit: 1 }])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unexpected key"), "{err}");
    }

    #[tokio::test]
    async fn oversized_deposits_are_refused_by_the_relay() {
        let keys = relay_keys();
        let (_store, dial) = spawn_relay(&keys);
        let r = exchange(
            dial(),
            &keys.public,
            vec![Request::Deposit { mailbox: vec![0; 32], blob: vec![0; Limits::default().max_blob + 1] }],
        )
        .await
        .unwrap();
        assert!(matches!(&r[0], Response::Error { reason } if reason.contains("larger")));
    }
}
