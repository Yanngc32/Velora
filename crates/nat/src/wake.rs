//! Wake-on-LAN: the magic packet, and sending it out of the right network.
//!
//! A sleeping PC answers nothing, so a wake always comes from a machine on its own LAN: the relay
//! PC or the phone on the home Wi-Fi, never from the internet (a router drops a forwarded magic
//! packet once it forgets the sleeping PC's ARP entry, and most refuse broadcast forwarding).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use anyhow::{bail, Context, Result};

use crate::addresses::{classify, local_macs, AddressClass, Ipv4Network};

/// A hardware (MAC) address.
pub type Mac = [u8; 6];

/// UDP ports the packet goes to: 9 (discard), the usual one, and 7 (echo), which some firmware listens on.
pub const PORTS: [u16; 2] = [9, 7];

/// The magic packet: six `0xFF` bytes, then the MAC address sixteen times.
pub fn magic_packet(mac: &Mac) -> [u8; 102] {
    let mut packet = [0xFF; 102];
    let (copies, _) = packet[6..].as_chunks_mut::<6>();
    for copy in copies {
        *copy = *mac;
    }
    packet
}

/// Reads `aa:bb:cc:dd:ee:ff` (or with `-`).
pub fn parse_mac(text: &str) -> Result<Mac> {
    let mut mac = [0u8; 6];
    let mut parts = text.trim().split([':', '-']);
    for byte in &mut mac {
        let part = parts.next().context("a MAC address has six parts")?;
        if part.len() != 2 {
            bail!("a MAC address has two hex digits in each part: {text:?}");
        }
        *byte = u8::from_str_radix(part, 16).with_context(|| format!("not a MAC address: {text:?}"))?;
    }
    if parts.next().is_some() {
        bail!("a MAC address has six parts: {text:?}");
    }
    Ok(mac)
}

/// Writes `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(mac: &Mac) -> String {
    mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

/// The IPv4 networks of this PC a broadcast can reach: those of its adapters that are up, have a
/// usable MAC and a real address (see [`local_macs`], which lists real adapters before virtual
/// ones). A phone hides its adapters' MAC addresses from apps, which would leave that list empty
/// although a magic packet needs only the network and not the sender's MAC: then every adapter
/// that is up and has a real address counts. Blocking: async callers should use `spawn_blocking`.
pub fn wake_networks() -> Vec<Ipv4Network> {
    let with_mac = usable(local_macs().into_iter().flat_map(|adapter| adapter.networks));
    if !with_mac.is_empty() {
        return with_mac;
    }
    let adapters = netdev::get_interfaces().into_iter().filter(|i| i.is_up() && !i.is_loopback());
    usable(adapters.flat_map(|i| i.ipv4).map(|net| Ipv4Network { addr: net.addr(), prefix_len: net.prefix_len() }))
}

/// Keeps what can carry a broadcast: no /31 or /32 (they have no broadcast address), nothing that is
/// not an address of a real network (link-local, loopback, fake-IP ranges), and no repeats.
fn usable(networks: impl IntoIterator<Item = Ipv4Network>) -> Vec<Ipv4Network> {
    let mut list: Vec<Ipv4Network> = Vec::new();
    for network in networks {
        let class = classify(IpAddr::V4(network.addr));
        let real = matches!(class, AddressClass::Private | AddressClass::Public | AddressClass::Shared);
        if network.prefix_len < 31 && real && !list.contains(&network) {
            list.push(network);
        }
    }
    list
}

/// The network `host` is on, among `networks`.
pub fn network_of(networks: &[Ipv4Network], host: Ipv4Addr) -> Option<Ipv4Network> {
    networks.iter().copied().find(|network| network.contains(host))
}

/// Sends the packet from `local` to each of `targets`. Binding to `local` makes the packet leave
/// through that adapter even on a PC with Wi-Fi, Ethernet and a VPN. Returns how many went out.
fn send(packet: &[u8], local: Ipv4Addr, targets: &[SocketAddrV4]) -> Result<usize> {
    let socket = UdpSocket::bind(SocketAddr::from((local, 0))).with_context(|| format!("binding {local}"))?;
    socket.set_broadcast(true).context("allowing broadcast")?;
    let mut sent = 0;
    let mut last_error = None;
    for target in targets {
        match socket.send_to(packet, target) {
            Ok(_) => sent += 1,
            Err(e) => {
                tracing::debug!("magic packet to {target} from {local}: {e}");
                last_error = Some(e);
            }
        }
    }
    match (sent, last_error) {
        (0, Some(e)) => Err(e).with_context(|| format!("sending the magic packet from {local}")),
        _ => Ok(sent),
    }
}

/// Wakes `mac` on `network`: the directed broadcast and the limited broadcast (`255.255.255.255`,
/// which Windows sends through the adapter the network belongs to), each on both ports. Returns
/// how many datagrams went out; an error only when none did.
pub fn wake_on(mac: &Mac, network: &Ipv4Network) -> Result<usize> {
    let targets: Vec<SocketAddrV4> = [network.broadcast(), Ipv4Addr::BROADCAST]
        .iter()
        .flat_map(|&ip| PORTS.map(|port| SocketAddrV4::new(ip, port)))
        .collect();
    let sent = send(&magic_packet(mac), network.addr, &targets)?;
    tracing::info!("magic packet for {} sent from {} ({sent} datagrams)", format_mac(mac), network.addr);
    Ok(sent)
}

/// Wakes `mac` on the network `host` (its last known address) is on. Errors when none of this PC's
/// networks contains it: this PC cannot wake what is not on its own LAN. Blocking, like
/// [`wake_networks`].
pub fn wake_lan_of(mac: &Mac, host: Ipv4Addr) -> Result<usize> {
    match network_of(&wake_networks(), host) {
        Some(network) => wake_on(mac, &network),
        None => bail!("{host} is not on a network of this PC"),
    }
}

/// Wakes `mac` on every network of this PC, for when its address is not known. Returns how many
/// datagrams went out in all; an error only when none did. Blocking, like [`wake_networks`].
pub fn wake_all(mac: &Mac) -> Result<usize> {
    let networks = wake_networks();
    if networks.is_empty() {
        bail!("this PC has no network to send a magic packet on");
    }
    let mut sent = 0;
    for network in &networks {
        match wake_on(mac, network) {
            Ok(n) => sent += n,
            Err(e) => tracing::warn!("{e:#}"),
        }
    }
    if sent == 0 {
        bail!("no magic packet could be sent");
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: Mac = [0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

    fn network(a: u8, b: u8, c: u8, d: u8, prefix_len: u8) -> Ipv4Network {
        Ipv4Network { addr: Ipv4Addr::new(a, b, c, d), prefix_len }
    }

    #[test]
    fn magic_packet_is_six_ff_then_the_mac_sixteen_times() {
        let packet = magic_packet(&MAC);
        assert_eq!(packet.len(), 102);
        assert_eq!(packet[..6], [0xFF; 6]);
        for copy in packet[6..].chunks(6) {
            assert_eq!(copy, MAC);
        }
    }

    #[test]
    fn macs_parse_and_print() {
        assert_eq!(parse_mac("02:1a:2b:3c:4d:5e").unwrap(), MAC);
        assert_eq!(parse_mac(" 02-1A-2B-3C-4D-5E ").unwrap(), MAC);
        assert_eq!(format_mac(&MAC), "02:1a:2b:3c:4d:5e");
        for bad in
            ["", "02:1a:2b:3c:4d", "02:1a:2b:3c:4d:5e:6f", "02:1a:2b:3c:4d:5", "gg:1a:2b:3c:4d:5e", "021a2b3c4d5e"]
        {
            assert!(parse_mac(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_host_is_woken_on_the_network_it_is_on() {
        let (wifi, vpn) = (network(192, 168, 1, 20, 24), network(10, 8, 0, 2, 24));
        let networks = [wifi, vpn];
        assert_eq!(network_of(&networks, Ipv4Addr::new(10, 8, 0, 9)), Some(vpn));
        assert_eq!(network_of(&networks, Ipv4Addr::new(192, 168, 1, 50)), Some(wifi));
        assert_eq!(network_of(&networks, Ipv4Addr::new(172, 16, 0, 1)), None);
        assert_eq!(wifi.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert!(wake_lan_of(&MAC, Ipv4Addr::new(203, 0, 113, 5)).is_err());
    }

    #[test]
    fn only_networks_that_can_carry_a_broadcast_are_kept() {
        let kept = usable([
            network(192, 168, 1, 20, 24),
            network(192, 168, 1, 20, 24),
            network(10, 0, 0, 5, 32),
            network(10, 0, 0, 6, 31),
            network(169, 254, 3, 4, 16),
            network(127, 0, 0, 1, 8),
            network(100, 64, 0, 9, 10),
        ]);
        assert_eq!(kept, [network(192, 168, 1, 20, 24), network(100, 64, 0, 9, 10)]);
    }

    #[test]
    fn the_packet_arrives_whole() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let target = match receiver.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4,
            SocketAddr::V6(_) => unreachable!(),
        };
        let sent = send(&magic_packet(&MAC), Ipv4Addr::LOCALHOST, &[target]).unwrap();
        assert_eq!(sent, 1);
        let mut buf = [0u8; 256];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(buf[..n], magic_packet(&MAC));
    }

    /// Wakes a real PC on this LAN, with `VELORA_WAKE_MAC=aa:bb:cc:dd:ee:ff` set:
    /// `cargo test -p velora-nat wake::tests::manual -- --ignored --nocapture`.
    #[test]
    #[ignore = "sends a real magic packet on the LAN"]
    fn manual() {
        let mac = parse_mac(&std::env::var("VELORA_WAKE_MAC").expect("set VELORA_WAKE_MAC")).unwrap();
        println!("networks: {:?}", wake_networks());
        println!("datagrams sent: {}", wake_all(&mac).unwrap());
    }
}
