//! Finding a host whose address changed, without a server: a signed record in the BitTorrent
//! Mainline DHT (BEP 44), sealed so that only the devices paired with the host can read it.
//! See `docs/nat-traversal.md`, phase 2.

pub mod keys;
pub mod node;
pub mod punch_item;
pub mod record;
pub mod seal;
