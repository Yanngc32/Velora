//! Wake-on-LAN: the magic packet, and sending it out of the right network.
//!
//! A sleeping PC answers nothing, so a wake always comes from a machine on its own LAN: the relay
//! PC or the phone on the home Wi-Fi, never from the internet (a router drops a forwarded magic
//! packet once it forgets the sleeping PC's ARP entry, and most refuse broadcast forwarding).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use anyhow::{bail, Context, Result};

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

/// One IPv4 network of this PC that a magic packet can leave through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lan {
    /// This PC's address on the network.
    pub local: Ipv4Addr,
    pub prefix_len: u8,
    /// The directed broadcast address of the network (`192.168.1.255` for `192.168.1.0/24`).
    pub broadcast: Ipv4Addr,
}

fn mask(prefix_len: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix_len.min(32))).unwrap_or(0)
}

impl Lan {
    pub fn new(local: Ipv4Addr, prefix_len: u8) -> Self {
        Self { local, prefix_len, broadcast: Ipv4Addr::from(u32::from(local) | !mask(prefix_len)) }
    }

    /// Whether `ip` is on this network.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = mask(self.prefix_len);
        u32::from(ip) & mask == u32::from(self.local) & mask
    }
}

/// The networks of this PC a broadcast can reach: up, not loopback or a tunnel, with a real
/// broadcast address (so no /31 or /32) and not the link-local range a PC gives itself without DHCP.
pub fn local_lans() -> Vec<Lan> {
    let mut lans = Vec::new();
    for interface in netdev::get_interfaces() {
        if !interface.is_up() || interface.is_loopback() || interface.is_point_to_point() {
            continue;
        }
        for net in &interface.ipv4 {
            let local = net.addr();
            if net.prefix_len() >= 31 || local.is_link_local() || local.is_unspecified() {
                continue;
            }
            lans.push(Lan::new(local, net.prefix_len()));
        }
    }
    lans
}

/// The network `host` is on, among `lans`.
pub fn lan_of(lans: &[Lan], host: Ipv4Addr) -> Option<Lan> {
    lans.iter().copied().find(|lan| lan.contains(host))
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

/// Wakes `mac` on `lan`: the directed broadcast and the limited broadcast (`255.255.255.255`, which
/// Windows sends through the adapter `local` belongs to), each on both ports. Returns how many
/// datagrams went out; an error only when none did.
pub fn wake_on(mac: &Mac, lan: &Lan) -> Result<usize> {
    let targets: Vec<SocketAddrV4> = [lan.broadcast, Ipv4Addr::BROADCAST]
        .iter()
        .flat_map(|&ip| PORTS.map(|port| SocketAddrV4::new(ip, port)))
        .collect();
    let sent = send(&magic_packet(mac), lan.local, &targets)?;
    tracing::info!("magic packet for {} sent from {} ({sent} datagrams)", format_mac(mac), lan.local);
    Ok(sent)
}

/// Wakes `mac` on the network `host` (its last known address) is on. Errors when none of this PC's
/// networks contains it: this PC cannot wake what is not on its own LAN.
pub fn wake_lan_of(mac: &Mac, host: Ipv4Addr) -> Result<usize> {
    match lan_of(&local_lans(), host) {
        Some(lan) => wake_on(mac, &lan),
        None => bail!("{host} is not on a network of this PC"),
    }
}

/// Wakes `mac` on every network of this PC, for when its address is not known. Returns how many
/// datagrams went out in all; an error only when none did.
pub fn wake_all(mac: &Mac) -> Result<usize> {
    let lans = local_lans();
    if lans.is_empty() {
        bail!("this PC has no network to send a magic packet on");
    }
    let mut sent = 0;
    for lan in &lans {
        match wake_on(mac, lan) {
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
    fn lan_knows_its_broadcast_and_its_hosts() {
        let lan = Lan::new(Ipv4Addr::new(192, 168, 1, 20), 24);
        assert_eq!(lan.broadcast, Ipv4Addr::new(192, 168, 1, 255));
        assert!(lan.contains(Ipv4Addr::new(192, 168, 1, 7)));
        assert!(!lan.contains(Ipv4Addr::new(192, 168, 2, 7)));

        let wide = Lan::new(Ipv4Addr::new(10, 1, 2, 3), 16);
        assert_eq!(wide.broadcast, Ipv4Addr::new(10, 1, 255, 255));
        assert!(wide.contains(Ipv4Addr::new(10, 1, 200, 9)));
        assert!(!wide.contains(Ipv4Addr::new(10, 2, 0, 1)));

        // The edges of the prefix length do not overflow the shift.
        assert_eq!(Lan::new(Ipv4Addr::new(10, 0, 0, 1), 0).broadcast, Ipv4Addr::BROADCAST);
        assert!(Lan::new(Ipv4Addr::new(10, 0, 0, 1), 0).contains(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!Lan::new(Ipv4Addr::new(10, 0, 0, 1), 32).contains(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn the_host_is_woken_on_the_network_it_is_on() {
        let wifi = Lan::new(Ipv4Addr::new(192, 168, 1, 20), 24);
        let vpn = Lan::new(Ipv4Addr::new(10, 8, 0, 2), 24);
        let lans = [wifi, vpn];
        assert_eq!(lan_of(&lans, Ipv4Addr::new(10, 8, 0, 9)), Some(vpn));
        assert_eq!(lan_of(&lans, Ipv4Addr::new(192, 168, 1, 50)), Some(wifi));
        assert_eq!(lan_of(&lans, Ipv4Addr::new(172, 16, 0, 1)), None);
        assert!(wake_lan_of(&MAC, Ipv4Addr::new(203, 0, 113, 5)).is_err());
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
        println!("networks: {:?}", local_lans());
        println!("datagrams sent: {}", wake_all(&mac).unwrap());
    }
}
