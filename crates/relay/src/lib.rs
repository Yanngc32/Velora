//! Relaying a client's QUIC packets to a host that cannot be reached directly. The relay is a
//! paired PC (or `velora-host run --relay-only` on a VPS); both ends dial out to it and it
//! copies datagrams between them without being able to read them. See
//! `docs/nat-traversal.md`, phase 4.

pub mod forward;
pub mod frame;
