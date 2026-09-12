# SecureText

A peer-to-peer, end-to-end encrypted messaging application — Discord-like in
UX (servers, channels, roles, voice), decentralized in architecture (no
central account database, no server that can read or be compelled to hand
over message content).

This repository currently holds **Phase 0** deliverables only: the threat
model, cryptographic design, network architecture, and technology stack
decisions that every later phase builds on. No application code has been
written yet — see [docs/roadmap.md](docs/roadmap.md) for the full phase plan.

## Status

**Phase 0 — Spec & Threat Model** (in progress)

## Documents

- [docs/threat-model.md](docs/threat-model.md) — what SecureText protects against, and what it explicitly does not
- [docs/crypto-spec.md](docs/crypto-spec.md) — key management, 1:1 encryption, group encryption
- [docs/architecture.md](docs/architecture.md) — networking, discovery, NAT traversal, offline delivery, server/channel model
- [docs/tech-stack.md](docs/tech-stack.md) — concrete libraries and tools chosen, with rationale
- [docs/platform-support.md](docs/platform-support.md) — supported OS matrix (Ubuntu, Fedora, Windows 10/11) and cross-platform implementation notes
- [docs/roadmap.md](docs/roadmap.md) — phase-by-phase development plan

## Supported platforms

Ubuntu (22.04+), Fedora (current release), Windows 10 (21H2+), and Windows
11. See [docs/platform-support.md](docs/platform-support.md) for details.
macOS is not an official v1 target.
