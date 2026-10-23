//! Wake-on-LAN support, host side. Filled in by ticket E6; the plumbing it plugs into is
//! `reach/mod.rs`, which E6 does not edit.

/// The MAC address of the adapter to wake this PC through (`velora_nat::addresses::local_macs`
/// already picks real adapters before virtual ones). The host asks for it from a blocking thread
/// when it starts and every half hour (sooner, with growing gaps, while it has none), keeps the answer in
/// `ReachState::mac`, and puts it in `HostMsg::Reach` and, through E3, in the DHT record; hooks
/// read it from the state rather than calling this. `None` when there is no adapter to wake.
pub fn local_mac() -> Option<[u8; 6]> {
    // reach: filled in by E6
    None
}
