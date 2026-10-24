//! Wake-on-LAN support, host side: the MAC address a relay sends the magic packet to when a paired
//! device asks it to wake this computer. The plumbing it plugs into is `reach/mod.rs`.

use velora_nat::addresses::{self, LocalMac};

/// The MAC address of the adapter to wake this PC through: the first of its adapters that is not a
/// virtual one (a VM switch, a container or a VPN makes up its address, and a magic packet sent to
/// that wakes nothing), `None` when there is no such adapter. `velora_nat::addresses::local_macs`
/// already lists real adapters before virtual ones, the one that carries the default route first.
///
/// Blocking, as listing the adapters is. The host asks for it from a blocking thread when it starts
/// and every few minutes, so that a laptop that moves to another adapter tells the relays and the DHT
/// its new address (sooner, with growing gaps, while it has none). It keeps the answer in
/// `ReachState::mac` and puts it in `HostMsg::Reach` and, through E3, in the DHT record; hooks read
/// it from the state rather than calling this.
pub fn local_mac() -> Option<[u8; 6]> {
    let adapters = addresses::local_macs();
    let mac = choose(&adapters);
    if mac.is_none() {
        tracing::debug!("no adapter to wake this computer through ({} virtual)", adapters.len());
    }
    mac
}

/// The first adapter of `adapters` that is not virtual, whatever the order they come in.
fn choose(adapters: &[LocalMac]) -> Option<[u8; 6]> {
    adapters.iter().find(|adapter| !adapter.virtual_adapter).map(|adapter| adapter.mac)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use velora_nat::addresses::Ipv4Network;

    use super::*;

    fn adapter(n: u8, virtual_adapter: bool) -> LocalMac {
        LocalMac {
            // The ranges meant for documentation (RFC 7042, RFC 5737): the repository is public.
            mac: [0x00, 0x00, 0x5e, 0x00, 0x53, n],
            name: format!("adapter {n}"),
            networks: vec![Ipv4Network { addr: Ipv4Addr::new(198, 51, 100, n), prefix_len: 24 }],
            virtual_adapter,
        }
    }

    #[test]
    fn the_first_real_adapter_is_the_one_to_wake_through() {
        let adapters = [adapter(1, false), adapter(2, false), adapter(3, true)];
        assert_eq!(choose(&adapters), Some(adapters[0].mac));
    }

    #[test]
    fn a_virtual_adapter_ahead_of_a_real_one_is_passed_over() {
        let adapters = [adapter(1, true), adapter(2, true), adapter(3, false), adapter(4, false)];
        assert_eq!(choose(&adapters), Some(adapters[2].mac));
    }

    #[test]
    fn a_computer_with_no_real_adapter_has_nothing_to_wake_it_through() {
        assert_eq!(choose(&[]), None);
        assert_eq!(choose(&[adapter(1, true), adapter(2, true)]), None);
    }

    #[test]
    fn this_computers_answer_is_the_choice_from_its_adapters() {
        // The real list, with a check that the adapters did not change while it was read.
        let before = addresses::local_macs();
        let mac = local_mac();
        let after = addresses::local_macs();
        if before == after {
            assert_eq!(mac, choose(&before));
        }
        if let Some(mac) = mac {
            assert!(mac != [0; 6] && mac[0] & 1 == 0, "a unicast address: {mac:02x?}");
        }
    }
}
