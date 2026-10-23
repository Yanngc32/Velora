//! Wake-on-LAN support, host side. Filled in by ticket E6; the plumbing it plugs into is
//! `reach/mod.rs`, which E6 does not edit.

use std::net::IpAddr;

/// The MAC address of the adapter to wake this PC through (`velora_nat::addresses::local_macs`
/// already picks real adapters before virtual ones). The host asks for it from a blocking thread
/// when it starts and every half hour (sooner, with growing gaps, while it has none), keeps the answer in
/// `ReachState::mac`, and puts it in `HostMsg::Reach` and, through E3, in the DHT record; hooks
/// read it from the state rather than calling this. `None` when there is no adapter to wake.
pub fn local_mac() -> Option<[u8; 6]> {
    // reach: filled in by E6
    None
}

/// Whether `peer` is on a network this computer is on too (one of the IPv4 networks of its real
/// adapters), so a magic packet sent from here reaches it. The relay (E4) asks before it wakes a
/// registered host from the address that host's connection came from; an IPv4-mapped address
/// counts as its IPv4 form. `false` for anything it cannot place.
pub fn same_lan(peer: IpAddr) -> bool {
    // reach: filled in by E6
    let _ = peer;
    false
}
