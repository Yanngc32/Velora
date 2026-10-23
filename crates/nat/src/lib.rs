//! What the router and the network can tell us about reaching this PC from outside, with no
//! server in the way: port mappings (NAT-PMP, UPnP IGD), the public and IPv6 addresses, the
//! endpoint a NAT shows the world, and Wake-on-LAN. See `docs/nat-traversal.md`.
//!
//! Every function here is optional help: a failure is an error for the caller to log or show,
//! never a panic and never a reason to stop the host.

pub mod addresses;
pub mod mapping;
pub mod observe;
pub mod wake;
