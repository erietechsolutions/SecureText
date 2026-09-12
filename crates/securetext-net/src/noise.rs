//! Noise transport defense-in-depth layer (crypto-spec.md §4).
//!
//! This runs on top of the onion-service `DataStream` and is independent of
//! both Tor's own transport crypto and MLS's message-layer E2EE — it
//! authenticates the *specific* peer's long-term Noise static key (not just
//! "some onion service responded") and adds an encryption layer that
//! doesn't depend on trusting Tor's transport crypto exclusively.
//!
//! Uses Noise_XX: neither side needs to know the other's static key ahead
//! of the handshake (both are revealed and verified *during* it), which
//! fits Phase 1's manual/out-of-band key exchange model (the Noise static
//! public key is shared alongside the onion address, the same way an
//! invite link will carry it in Phase 2). The caller is responsible for
//! comparing the returned remote static key against the expected value
//! obtained out-of-band — this module only performs the cryptographic
//! handshake, not the trust decision.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::NetError;

/// Must match `securetext_identity::NOISE_PATTERN` exactly.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

const MAX_NOISE_MESSAGE: usize = 65535;

/// An established Noise session, ready to encrypt/decrypt application data.
pub struct NoiseTransport {
    transport: snow::TransportState,
}

impl NoiseTransport {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetError> {
        let mut buf = vec![0u8; plaintext.len() + 64]; // Noise tag + framing headroom
        let len = self
            .transport
            .write_message(plaintext, &mut buf)
            .map_err(|e| NetError::Noise(format!("{e:?}")))?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetError> {
        let mut buf = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut buf)
            .map_err(|e| NetError::Noise(format!("{e:?}")))?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Perform the Noise_XX handshake as the initiator (the dialing side).
/// Returns the established transport plus the remote's presented static
/// public key, which the caller must verify against the expected value
/// obtained out-of-band before trusting this connection.
pub async fn handshake_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    local_static_private_key: &[u8],
) -> Result<(NoiseTransport, Vec<u8>), NetError> {
    let mut state = snow::Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"))
        .local_private_key(local_static_private_key)
        .map_err(|e| NetError::Noise(format!("{e:?}")))?
        .build_initiator()
        .map_err(|e| NetError::Noise(format!("{e:?}")))?;

    // XX: -> e, s
    write_handshake_message(stream, &mut state, &[]).await?;
    // <- e, ee, s, es
    read_handshake_message(stream, &mut state).await?;
    // -> s, se
    write_handshake_message(stream, &mut state, &[]).await?;

    finish_handshake(state)
}

/// Perform the Noise_XX handshake as the responder (the accepting side).
pub async fn handshake_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    local_static_private_key: &[u8],
) -> Result<(NoiseTransport, Vec<u8>), NetError> {
    let mut state = snow::Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"))
        .local_private_key(local_static_private_key)
        .map_err(|e| NetError::Noise(format!("{e:?}")))?
        .build_responder()
        .map_err(|e| NetError::Noise(format!("{e:?}")))?;

    // -> e, s
    read_handshake_message(stream, &mut state).await?;
    // <- e, ee, s, es
    write_handshake_message(stream, &mut state, &[]).await?;
    // -> s, se
    read_handshake_message(stream, &mut state).await?;

    finish_handshake(state)
}

fn finish_handshake(state: snow::HandshakeState) -> Result<(NoiseTransport, Vec<u8>), NetError> {
    let remote_static = state
        .get_remote_static()
        .ok_or_else(|| NetError::Noise("handshake completed with no remote static key".into()))?
        .to_vec();
    let transport = state
        .into_transport_mode()
        .map_err(|e| NetError::Noise(format!("{e:?}")))?;
    Ok((NoiseTransport { transport }, remote_static))
}

async fn write_handshake_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    state: &mut snow::HandshakeState,
    payload: &[u8],
) -> Result<(), NetError> {
    let mut buf = vec![0u8; MAX_NOISE_MESSAGE];
    let len = state
        .write_message(payload, &mut buf)
        .map_err(|e| NetError::Noise(format!("{e:?}")))?;
    let len_u32 = u32::try_from(len).map_err(|_| NetError::Noise("handshake message too large".into()))?;
    stream
        .write_all(&len_u32.to_be_bytes())
        .await
        .map_err(NetError::Io)?;
    stream.write_all(&buf[..len]).await.map_err(NetError::Io)?;
    // Learned the hard way (tech-stack.md's implementation findings):
    // DataStream buffers writes internally and needs an explicit flush, or
    // the peer's corresponding read blocks forever.
    stream.flush().await.map_err(NetError::Io)?;
    Ok(())
}

async fn read_handshake_message<S: AsyncRead + Unpin>(
    stream: &mut S,
    state: &mut snow::HandshakeState,
) -> Result<(), NetError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.map_err(NetError::Io)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_NOISE_MESSAGE {
        return Err(NetError::Noise("handshake message too large".into()));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await.map_err(NetError::Io)?;
    let mut discard = vec![0u8; len];
    state
        .read_message(&msg, &mut discard)
        .map_err(|e| NetError::Noise(format!("{e:?}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local-only correctness proof for the handshake and the resulting
    /// transport encryption, using an in-memory duplex pipe instead of a
    /// real onion-service connection -- no live Tor network needed to
    /// verify the Noise cryptography itself is wired correctly.
    #[tokio::test]
    async fn handshake_and_transport_round_trip_over_duplex_pipe() {
        let (mut initiator_stream, mut responder_stream) = tokio::io::duplex(4096);

        let initiator_keys = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let responder_keys = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();

        let (initiator_result, responder_result) = tokio::join!(
            handshake_initiator(&mut initiator_stream, &initiator_keys.private),
            handshake_responder(&mut responder_stream, &responder_keys.private)
        );

        let (mut initiator_transport, initiator_saw_remote) =
            initiator_result.expect("initiator handshake");
        let (mut responder_transport, responder_saw_remote) =
            responder_result.expect("responder handshake");

        // Each side should see exactly the other's real static public key --
        // this is the "authenticate the specific peer identity" property
        // crypto-spec.md §4 asks for.
        assert_eq!(initiator_saw_remote, responder_keys.public);
        assert_eq!(responder_saw_remote, initiator_keys.public);

        let ciphertext = initiator_transport.encrypt(b"hello over noise").unwrap();
        let plaintext = responder_transport.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, b"hello over noise");

        let reply_ciphertext = responder_transport.encrypt(b"hi back").unwrap();
        let reply_plaintext = initiator_transport.decrypt(&reply_ciphertext).unwrap();
        assert_eq!(reply_plaintext, b"hi back");
    }
}
