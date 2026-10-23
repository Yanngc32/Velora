//! Which addresses of this PC are public, shared (CGNAT), private or IPv6, and its MACs.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// What kind of network an IP address belongs to, which says whether another network can reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressClass {
    /// A globally routable IPv4 address.
    Public,
    /// RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. A router that shows one of these as its
    /// external address sits behind another NAT.
    Private,
    /// 100.64.0.0/10 (RFC 6598): carrier-grade NAT, and also what Tailscale and Netbird hand out.
    Shared,
    /// 169.254.0.0/16 and fe80::/10.
    LinkLocal,
    /// 127.0.0.0/8 and ::1.
    Loopback,
    /// fc00::/7, the private range of IPv6.
    UniqueLocal,
    /// A globally routable IPv6 address: 2000::/3 without the documentation and tunnel ranges.
    GlobalV6,
    /// Everything else: unspecified, multicast, broadcast, reserved and documentation ranges, and
    /// the IPv6 tunnel ranges (Teredo, 6to4) that look global but cannot take a connection.
    Other,
}

impl AddressClass {
    /// Whether the address is routable from the whole internet (`Public` or `GlobalV6`), so worth
    /// advertising as a place to connect to.
    pub fn is_global(self) -> bool {
        matches!(self, AddressClass::Public | AddressClass::GlobalV6)
    }
}

/// Tells what kind of network `ip` belongs to. An IPv4-mapped IPv6 address (what a dual-stack
/// socket reports for an IPv4 peer) is classified as the IPv4 address it wraps.
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let [a, b, c, _] = ip.octets();
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_private() {
        AddressClass::Private
    } else if a == 100 && (64..128).contains(&b) {
        AddressClass::Shared
    } else if ip.is_link_local() {
        AddressClass::LinkLocal
    } else if a == 0 // "this network"
        || a >= 224 // multicast, reserved, broadcast
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // benchmarking, also used by fake-IP VPN adapters
        || ip.is_documentation()
    {
        AddressClass::Other
    } else {
        AddressClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let s = ip.segments();
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if s[0] & 0xffc0 == 0xfe80 {
        AddressClass::LinkLocal
    } else if s[0] & 0xfe00 == 0xfc00 {
        AddressClass::UniqueLocal
    } else if s[0] & 0xe000 != 0x2000 {
        AddressClass::Other
    } else {
        // Inside 2000::/3 but not for hosts: 6to4, IETF protocol assignments (Teredo among them) and
        // the two documentation prefixes.
        let reserved = s[0] == 0x2002
            || (s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
            || (s[0] == 0x3fff && s[1] < 0x1000);
        if reserved {
            AddressClass::Other
        } else {
            AddressClass::GlobalV6
        }
    }
}

/// A global IPv6 address of this PC. See [`global_ipv6`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalV6 {
    /// The address.
    pub addr: Ipv6Addr,
    /// Index of the interface that carries it, to keep one address per interface.
    pub interface: u32,
    /// How long the address stays valid; `None` when it does not expire or the OS does not say.
    pub valid_for: Option<Duration>,
}

/// An IPv6 address as the OS reports it, before filtering.
struct V6Candidate {
    addr: Ipv6Addr,
    interface: u32,
    /// Seconds the address stays valid; `FOREVER` for no end, `None` when the OS does not say.
    valid_secs: Option<u32>,
    /// False for addresses that are tentative, duplicate, deprecated or not meant for applications.
    usable: bool,
    /// Configured by hand (or by a VPN driver) rather than given by the network.
    manual: bool,
}

/// How Windows (and DHCPv6 and router advertisements) say an address never expires.
const FOREVER: u32 = u32::MAX;

/// Turns what the OS reported into the list [`global_ipv6`] returns.
fn best_first(candidates: Vec<V6Candidate>) -> Vec<GlobalV6> {
    let mut list: Vec<V6Candidate> = candidates
        .into_iter()
        .filter(|c| c.usable && !c.manual && classify(IpAddr::V6(c.addr)) == AddressClass::GlobalV6)
        .collect();
    // Stable, so addresses with the same lifetime keep the order the OS gave them in.
    list.sort_by_key(|c| std::cmp::Reverse(c.valid_secs.unwrap_or(FOREVER)));
    let mut seen = HashSet::new();
    list.retain(|c| seen.insert(c.addr));
    list.into_iter()
        .map(|c| GlobalV6 {
            addr: c.addr,
            interface: c.interface,
            valid_for: c.valid_secs.filter(|&s| s != FOREVER).map(|s| Duration::from_secs(s.into())),
        })
        .collect()
}

/// The global IPv6 addresses of this PC, best first, to advertise as places to connect to.
///
/// On Windows they come from `GetAdaptersAddresses`, which knows where each address came from
/// and how long it stays valid. Deprecated and tentative addresses are left out, and so are those
/// configured by hand: in practice they belong to VPN adapters (Hamachi gives itself a global
/// `2620:9b::` address, for one) and only the peers of that VPN can reach them. The rest come
/// valid-the-longest first, which puts the stable address ahead of the temporary (privacy) ones,
/// which change daily but still accept connections while they are valid. Elsewhere the origin and
/// the lifetimes are unknown and every global address of an up interface is listed in the order
/// the OS gives. Link-local, unique local and tunnel (Teredo, 6to4) addresses are never listed.
///
/// For one address per interface, keep the first entry of each `interface`. Whether the router
/// lets a connection in is a different matter, which only a client trying it can tell.
///
/// Synchronous but quick (one OS call). Async callers can use it directly.
pub fn global_ipv6() -> Vec<GlobalV6> {
    #[cfg(windows)]
    {
        match win::v6_candidates() {
            Ok(candidates) => return best_first(candidates),
            Err(e) => tracing::warn!("GetAdaptersAddresses failed ({e}); listing IPv6 addresses without lifetimes"),
        }
    }
    best_first(netdev_candidates(&netdev::get_interfaces()))
}

/// The IPv6 addresses `netdev` sees, which carry no lifetimes.
fn netdev_candidates(interfaces: &[netdev::Interface]) -> Vec<V6Candidate> {
    interfaces
        .iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .flat_map(|i| {
            i.ipv6.iter().map(move |net| V6Candidate {
                addr: net.addr(),
                interface: i.index,
                valid_secs: None,
                usable: true,
                manual: false,
            })
        })
        .collect()
}

#[cfg(windows)]
mod win {
    use std::io;
    use std::net::Ipv6Addr;

    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_ADDRESS_TRANSIENT,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{
        IpDadStatePreferred, IpPrefixOriginManual, AF_INET6, SOCKADDR_IN6, SOCKET_ADDRESS,
    };

    use super::V6Candidate;

    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    // Teredo, 6to4 and ISATAP live on these: addresses that look global but take no connection.
    const IF_TYPE_TUNNEL: u32 = 131;

    /// Every IPv6 unicast address of the adapters that are up, with its lifetime and state.
    pub fn v6_candidates() -> io::Result<Vec<V6Candidate>> {
        // u64 elements, since IP_ADAPTER_ADDRESSES needs 8-byte alignment.
        let mut buf: Vec<u64> = vec![0; 4096];
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut attempts = 0;
        loop {
            let mut len = (buf.len() * 8) as u32;
            // SAFETY: `buf` is writable for `len` bytes and aligned for the adapter structures.
            let ret = unsafe {
                GetAdaptersAddresses(AF_INET6.0.into(), flags, None, Some(buf.as_mut_ptr().cast()), &mut len)
            };
            if ret == NO_ERROR.0 {
                break;
            }
            // No adapter has IPv6 at all (it is switched off): nothing to list, not a failure.
            if ret == ERROR_NO_DATA.0 {
                return Ok(Vec::new());
            }
            // The list can grow between the two calls, so a few attempts.
            if ret == ERROR_BUFFER_OVERFLOW.0 && attempts < 4 {
                attempts += 1;
                buf.resize((len as usize).div_ceil(8), 0);
                continue;
            }
            return Err(io::Error::from_raw_os_error(ret as i32));
        }

        let mut out = Vec::new();
        let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            // SAFETY: GetAdaptersAddresses linked the structures inside `buf`, which stays untouched here.
            let a = unsafe { &*adapter };
            adapter = a.Next;
            if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == IF_TYPE_TUNNEL {
                continue;
            }
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: as above.
                let u = unsafe { &*unicast };
                unicast = u.Next;
                // SAFETY: the address belongs to the structure just read.
                let Some(addr) = (unsafe { v6_of(&u.Address) }) else { continue };
                // SAFETY: reading a plain integer out of the union.
                let address_flags = unsafe { u.Anonymous.Anonymous.Flags };
                out.push(V6Candidate {
                    addr,
                    interface: a.Ipv6IfIndex,
                    valid_secs: Some(u.ValidLifetime),
                    // Deprecated addresses still work for now but are about to go; transient ones
                    // are cluster addresses applications should not use.
                    usable: u.DadState == IpDadStatePreferred && address_flags & IP_ADAPTER_ADDRESS_TRANSIENT == 0,
                    manual: u.PrefixOrigin == IpPrefixOriginManual,
                });
            }
        }
        Ok(out)
    }

    /// The IPv6 address in a `SOCKET_ADDRESS`, if it holds one.
    ///
    /// # Safety
    /// `sa.lpSockaddr` must be null or point to `sa.iSockaddrLength` readable bytes.
    unsafe fn v6_of(sa: &SOCKET_ADDRESS) -> Option<Ipv6Addr> {
        let len = usize::try_from(sa.iSockaddrLength).unwrap_or(0);
        if sa.lpSockaddr.is_null() || len < std::mem::size_of::<SOCKADDR_IN6>() {
            return None;
        }
        // SAFETY: checked above; unaligned, since nothing promises the alignment of the sockaddr.
        let sin6 = unsafe { std::ptr::read_unaligned(sa.lpSockaddr.cast::<SOCKADDR_IN6>()) };
        // SAFETY: every variant of the union is plain bytes.
        (sin6.sin6_family == AF_INET6).then(|| Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte }))
    }
}

/// An IPv4 network this PC is on: its own address there and the prefix length of the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Network {
    /// The PC's address on the network.
    pub addr: Ipv4Addr,
    /// Number of leading bits shared by every address of the network (0 to 32).
    pub prefix_len: u8,
}

impl Ipv4Network {
    fn mask(&self) -> u32 {
        match self.prefix_len {
            0 => 0,
            1..=31 => u32::MAX << (32 - u32::from(self.prefix_len)),
            _ => u32::MAX,
        }
    }

    /// Whether `ip` is on this network, which is how to tell that a peer is on the same LAN.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) ^ u32::from(self.addr)) & self.mask() == 0
    }

    /// The directed broadcast address of the network, where a Wake-on-LAN packet goes.
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }
}

/// A network adapter of this PC that can be woken by its MAC. See [`local_macs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMac {
    /// The adapter's hardware address.
    pub mac: [u8; 6],
    /// The adapter's name as the OS shows it, for logs.
    pub name: String,
    /// The IPv4 networks the adapter is connected to. Never empty.
    pub networks: Vec<Ipv4Network>,
    /// Probably a software adapter (VM switch, container, VPN): its MAC is made up, so it is not
    /// where to send a magic packet or to look for a LAN. A real adapter set to use a random
    /// hardware address looks the same.
    pub virtual_adapter: bool,
}

/// An interface as the OS reports it, before filtering.
struct Adapter {
    name: String,
    index: u32,
    mac: Option<[u8; 6]>,
    up: bool,
    loopback: bool,
    /// Carries the default route.
    default: bool,
    v4: Vec<Ipv4Network>,
}

/// MAC prefixes of virtual adapters: VMware, Hyper-V, Parallels, Xen and VirtualBox.
const VIRTUAL_OUIS: [[u8; 3]; 9] = [
    [0x00, 0x05, 0x69],
    [0x00, 0x0c, 0x29],
    [0x00, 0x1c, 0x14],
    [0x00, 0x50, 0x56],
    [0x00, 0x03, 0xff],
    [0x00, 0x15, 0x5d],
    [0x00, 0x1c, 0x42],
    [0x00, 0x16, 0x3e],
    [0x08, 0x00, 0x27],
];

/// A MAC that cannot wake anything: unset, broadcast, multicast, or the loopback pseudo-adapters
/// of Windows and Npcap.
fn is_unusable_mac(mac: &[u8; 6]) -> bool {
    *mac == [0; 6] || *mac == [0xff; 6] || mac[0] & 1 != 0 || *mac == [0x02, 0x00, 0x4c, 0x4f, 0x4f, 0x50]
}

/// Adapters made by software (VMs, containers, VPNs) have a made-up MAC, which the
/// locally-administered bit or a known VM prefix gives away.
fn is_virtual_mac(mac: &[u8; 6]) -> bool {
    mac[0] & 2 != 0 || VIRTUAL_OUIS.iter().any(|oui| mac[..3] == oui[..])
}

/// The networks of an adapter worth knowing: an address on 169.254/16 or in a fake-IP range says
/// the adapter is not on a real network.
fn real_networks(v4: Vec<Ipv4Network>) -> Vec<Ipv4Network> {
    let real = |n: &Ipv4Network| {
        let class = classify(IpAddr::V4(n.addr));
        n.prefix_len <= 32 && matches!(class, AddressClass::Private | AddressClass::Public | AddressClass::Shared)
    };
    v4.into_iter().filter(real).collect()
}

/// Turns the interfaces the OS reported into the list [`local_macs`] returns.
fn macs_of(adapters: Vec<Adapter>) -> Vec<LocalMac> {
    let mut list: Vec<(bool, u32, LocalMac)> = adapters
        .into_iter()
        .filter(|a| a.up && !a.loopback)
        .filter_map(|a| {
            let mac = a.mac.filter(|m| !is_unusable_mac(m))?;
            let networks = real_networks(a.v4);
            if networks.is_empty() {
                return None;
            }
            let virtual_adapter = is_virtual_mac(&mac);
            Some((!a.default, a.index, LocalMac { mac, name: a.name, networks, virtual_adapter }))
        })
        .collect();
    list.sort_by_key(|(not_default, index, m)| (m.virtual_adapter, *not_default, *index));
    list.into_iter().map(|(.., m)| m).collect()
}

/// The MACs of this PC's adapters that are up and connected to an IPv4 network, with the networks
/// each serves, best first: real adapters before virtual ones (VMs, containers, VPNs), the one
/// carrying the default route first among them. Use the first for "the MAC to wake this PC with"
/// and the networks of the adapters that are not `virtual_adapter` to tell whether a peer is on
/// the same LAN and where to broadcast.
///
/// Blocking: on Windows the interface list makes an ARP request for each gateway, which can take
/// a moment on a network that is not answering. Async callers should use `spawn_blocking`.
pub fn local_macs() -> Vec<LocalMac> {
    let adapters = netdev::get_interfaces()
        .into_iter()
        .map(|i| Adapter {
            up: i.is_up(),
            loopback: i.is_loopback(),
            default: i.default,
            index: i.index,
            mac: i.mac_addr.map(|m| m.octets()),
            v4: i.ipv4.iter().map(|n| Ipv4Network { addr: n.addr(), prefix_len: n.prefix_len() }).collect(),
            name: i.friendly_name.unwrap_or(i.name),
        })
        .collect();
    macs_of(adapters)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(ip: &str) -> AddressClass {
        classify(ip.parse().unwrap())
    }

    #[test]
    fn classifies_ipv4() {
        use AddressClass::*;
        let table = [
            ("8.8.8.8", Public),
            ("1.1.1.1", Public),
            ("172.15.255.255", Public),
            ("172.32.0.1", Public),
            ("100.63.255.255", Public),
            ("100.128.0.1", Public),
            ("223.255.255.254", Public),
            ("10.0.0.1", Private),
            ("10.255.255.255", Private),
            ("172.16.0.1", Private),
            ("172.31.255.254", Private),
            ("192.168.0.1", Private),
            ("192.168.255.254", Private),
            ("100.64.0.1", Shared),
            ("100.100.100.100", Shared),
            ("100.127.255.254", Shared),
            ("169.254.1.1", LinkLocal),
            ("127.0.0.1", Loopback),
            ("127.255.255.254", Loopback),
            ("0.0.0.0", Other),
            ("0.1.2.3", Other),
            ("192.0.0.8", Other),
            ("192.0.2.1", Other),
            ("198.18.0.1", Other),
            ("198.19.255.255", Other),
            ("198.51.100.7", Other),
            ("203.0.113.9", Other),
            ("224.0.0.1", Other),
            ("239.255.255.250", Other),
            ("240.0.0.1", Other),
            ("255.255.255.255", Other),
        ];
        for (ip, expected) in table {
            assert_eq!(class(ip), expected, "{ip}");
        }
    }

    #[test]
    fn classifies_ipv6() {
        use AddressClass::*;
        let table = [
            ("2606:4700:4700::1111", GlobalV6),
            ("2804:14d:1::1", GlobalV6),
            ("2a00:1450:4001::200e", GlobalV6),
            ("3ffe::1", GlobalV6),
            ("2001:200::1", GlobalV6),
            ("2001:4860:4860::8888", GlobalV6),
            ("fe80::1", LinkLocal),
            ("febf::1", LinkLocal),
            ("::1", Loopback),
            ("fc00::1", UniqueLocal),
            ("fd7a:115c:a1e0::1", UniqueLocal),
            ("fdff::1", UniqueLocal),
            ("::", Other),
            ("ff02::1", Other),
            ("fec0::1", Other),
            ("64:ff9b::808:808", Other),
            ("4000::1", Other),
            ("2001:db8::1", Other),
            ("3fff:0fff::1", Other),
            ("3fff:1000::1", GlobalV6),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", Other),
            ("2001:1ff::1", Other),
            ("2002:c000:204::1", Other),
        ];
        for (ip, expected) in table {
            assert_eq!(class(ip), expected, "{ip}");
        }
    }

    #[test]
    fn mapped_ipv6_is_classified_as_the_ipv4_inside() {
        assert_eq!(class("::ffff:192.168.1.5"), AddressClass::Private);
        assert_eq!(class("::ffff:8.8.8.8"), AddressClass::Public);
        assert_eq!(class("::ffff:100.64.0.1"), AddressClass::Shared);
        // Only the mapped form: the deprecated IPv4-compatible one is not an IPv4 address.
        assert_eq!(class("::808:808"), AddressClass::Other);
    }

    #[test]
    fn global_means_public_or_global_v6() {
        assert!(AddressClass::Public.is_global());
        assert!(AddressClass::GlobalV6.is_global());
        for class in [
            AddressClass::Private,
            AddressClass::Shared,
            AddressClass::LinkLocal,
            AddressClass::Loopback,
            AddressClass::UniqueLocal,
            AddressClass::Other,
        ] {
            assert!(!class.is_global(), "{class:?}");
        }
    }

    fn candidate(addr: &str, interface: u32, valid_secs: Option<u32>, usable: bool) -> V6Candidate {
        V6Candidate { addr: addr.parse().unwrap(), interface, valid_secs, usable, manual: false }
    }

    #[test]
    fn ipv6_leaves_out_addresses_configured_by_hand() {
        // A VPN adapter gives itself a global-looking address that only its peers can reach.
        let hamachi = V6Candidate { manual: true, ..candidate("2620:9b::10:2030", 23, Some(FOREVER), true) };
        let list = best_first(vec![hamachi, candidate("2804:14d:1::1", 7, Some(1000), true)]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].addr, "2804:14d:1::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn ipv6_prefers_the_longest_lifetime_and_skips_deprecated() {
        let day = 24 * 3600;
        let list = best_first(vec![
            candidate("2804:14d:1::aaaa", 7, Some(6 * day), true),  // temporary
            candidate("2804:14d:1::1", 7, Some(30 * day), true),    // stable
            candidate("2804:14d:1::dead", 7, Some(3 * day), false), // deprecated
            candidate("fe80::1", 7, Some(FOREVER), true),           // link-local
            candidate("fd00::5", 7, Some(FOREVER), true),           // unique local
            candidate("2001:0:4136:e378:8000:63bf:3fff:fdd2", 9, Some(FOREVER), true), // Teredo
            candidate("2a00:1450:4001::200e", 3, Some(FOREVER), true), // static, forever
        ]);
        let addrs: Vec<String> = list.iter().map(|g| g.addr.to_string()).collect();
        assert_eq!(addrs, ["2a00:1450:4001::200e", "2804:14d:1::1", "2804:14d:1::aaaa"]);
        assert_eq!(list[0].interface, 3);
        assert_eq!(list[0].valid_for, None, "forever is no expiry");
        assert_eq!(list[1].valid_for, Some(Duration::from_secs(30 * day as u64)));
    }

    #[test]
    fn ipv6_keeps_the_os_order_when_lifetimes_tie_or_are_unknown() {
        let list = best_first(vec![
            candidate("2804:14d:1::2", 7, None, true),
            candidate("2804:14d:1::1", 7, None, true),
            candidate("2804:14d:2::1", 8, None, true),
        ]);
        let addrs: Vec<String> = list.iter().map(|g| g.addr.to_string()).collect();
        assert_eq!(addrs, ["2804:14d:1::2", "2804:14d:1::1", "2804:14d:2::1"]);
        assert!(list.iter().all(|g| g.valid_for.is_none()));
    }

    #[test]
    fn ipv6_lists_an_address_once() {
        let list = best_first(vec![
            candidate("2804:14d:1::1", 7, Some(100), true),
            candidate("2804:14d:1::1", 8, Some(200), true),
        ]);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].interface, 8, "the better of the two entries stays");
    }

    #[test]
    fn real_ipv6_addresses_are_all_global() {
        // Whatever this machine has, including nothing.
        for g in global_ipv6() {
            assert_eq!(classify(IpAddr::V6(g.addr)), AddressClass::GlobalV6, "{g:?}");
        }
    }

    #[test]
    fn network_contains_and_broadcast() {
        let net = |addr: &str, prefix_len| Ipv4Network { addr: addr.parse().unwrap(), prefix_len };
        let lan = net("192.168.1.20", 24);
        assert!(lan.contains("192.168.1.1".parse().unwrap()));
        assert!(lan.contains("192.168.1.255".parse().unwrap()));
        assert!(!lan.contains("192.168.2.1".parse().unwrap()));
        assert_eq!(lan.broadcast(), Ipv4Addr::new(192, 168, 1, 255));

        let wide = net("10.20.30.40", 12);
        assert!(wide.contains("10.31.255.255".parse().unwrap()));
        assert!(!wide.contains("10.32.0.0".parse().unwrap()));
        assert_eq!(wide.broadcast(), Ipv4Addr::new(10, 31, 255, 255));

        let host = net("192.168.1.20", 32);
        assert!(host.contains("192.168.1.20".parse().unwrap()));
        assert!(!host.contains("192.168.1.21".parse().unwrap()));
        assert_eq!(host.broadcast(), Ipv4Addr::new(192, 168, 1, 20));

        let everything = net("192.168.1.20", 0);
        assert!(everything.contains("8.8.8.8".parse().unwrap()));
        assert_eq!(everything.broadcast(), Ipv4Addr::BROADCAST);

        let pair = net("10.0.0.1", 31);
        assert!(pair.contains("10.0.0.0".parse().unwrap()));
        assert!(!pair.contains("10.0.0.2".parse().unwrap()));
        assert_eq!(pair.broadcast(), Ipv4Addr::new(10, 0, 0, 1));
    }

    fn adapter(name: &str, index: u32, mac: Option<[u8; 6]>, v4: &[(&str, u8)]) -> Adapter {
        Adapter {
            name: name.into(),
            index,
            mac,
            up: true,
            loopback: false,
            default: false,
            v4: v4.iter().map(|(a, p)| Ipv4Network { addr: a.parse().unwrap(), prefix_len: *p }).collect(),
        }
    }

    const REAL: [u8; 6] = [0x3c, 0x7c, 0x3f, 0x11, 0x22, 0x33];
    const REAL_WIFI: [u8; 6] = [0x98, 0x59, 0x7a, 0x44, 0x55, 0x66];
    const HYPER_V: [u8; 6] = [0x00, 0x15, 0x5d, 0xaa, 0xbb, 0xcc];

    #[test]
    fn macs_put_real_adapters_first_and_the_default_route_before_the_rest() {
        let wifi = adapter("Wi-Fi", 3, Some(REAL_WIFI), &[("192.168.1.30", 24)]);
        let mut eth = adapter("Ethernet", 9, Some(REAL), &[("192.168.1.20", 24)]);
        eth.default = true;
        let vm = adapter("vEthernet (Default Switch)", 1, Some(HYPER_V), &[("172.28.64.1", 20)]);
        let list = macs_of(vec![vm, wifi, eth]);
        let names: Vec<&str> = list.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["Ethernet", "Wi-Fi", "vEthernet (Default Switch)"]);
        let flags: Vec<bool> = list.iter().map(|m| m.virtual_adapter).collect();
        assert_eq!(flags, [false, false, true]);
        assert_eq!(list[0].mac, REAL);
        assert_eq!(list[0].networks, [Ipv4Network { addr: "192.168.1.20".parse().unwrap(), prefix_len: 24 }]);
    }

    #[test]
    fn macs_skip_adapters_that_cannot_wake_or_are_not_connected() {
        let mut down = adapter("Down", 1, Some(REAL), &[("192.168.1.20", 24)]);
        down.up = false;
        let mut loopback = adapter("Loopback", 2, Some(REAL_WIFI), &[("127.0.0.1", 8)]);
        loopback.loopback = true;
        let list = macs_of(vec![
            down,
            loopback,
            adapter("No MAC", 3, None, &[("192.168.1.21", 24)]),
            adapter("Zero MAC (VPN)", 4, Some([0; 6]), &[("100.100.1.1", 32)]),
            adapter("Multicast MAC", 5, Some([0x01, 0, 0x5e, 0, 0, 1]), &[("192.168.1.22", 24)]),
            adapter("Npcap loopback", 6, Some([0x02, 0x00, 0x4c, 0x4f, 0x4f, 0x50]), &[("192.168.1.23", 24)]),
            adapter("No cable", 7, Some(REAL), &[("169.254.10.10", 16)]),
            adapter("No IPv4", 8, Some(REAL), &[]),
            adapter("Fake-IP VPN", 9, Some(REAL), &[("198.18.0.1", 16)]),
            adapter("Connected", 10, Some(REAL_WIFI), &[("169.254.10.10", 16), ("192.168.1.24", 24)]),
        ]);
        assert_eq!(list.len(), 1, "{list:?}");
        assert_eq!(list[0].name, "Connected");
        assert_eq!(list[0].networks.len(), 1, "the link-local address is not a network");
    }

    #[test]
    fn macs_with_a_made_up_address_come_last() {
        let random = [0x7a, 0x11, 0x22, 0x33, 0x44, 0x55]; // locally administered bit set
        let mut vpn = adapter("VPN", 1, Some(random), &[("10.8.0.2", 24)]);
        vpn.default = true; // a full-tunnel VPN takes the default route
        let list = macs_of(vec![vpn, adapter("Ethernet", 5, Some(REAL), &[("192.168.1.20", 24)])]);
        assert_eq!(list[0].name, "Ethernet");
        assert!(!list[0].virtual_adapter);
        assert_eq!(list[1].name, "VPN");
        assert!(list[1].virtual_adapter);
    }

    #[test]
    fn real_macs_are_wakeable() {
        for m in local_macs() {
            assert!(!is_unusable_mac(&m.mac), "{m:?}");
            assert!(!m.networks.is_empty(), "{m:?}");
        }
    }

    /// Prints what this PC reports, to compare with `ipconfig /all`:
    /// `cargo test -p velora-nat addresses::tests::print_this_pc -- --ignored --nocapture`
    #[test]
    #[ignore = "reads the real network configuration"]
    fn print_this_pc() {
        #[cfg(windows)]
        {
            println!("every IPv6 address of the adapters that are up, as Windows reports it (compare with Get-NetIPAddress):");
            match win::v6_candidates() {
                Ok(all) => {
                    for c in all {
                        let class = classify(IpAddr::V6(c.addr));
                        println!(
                            "  {} interface {} valid {:?}s usable {} manual {} -> {class:?}",
                            c.addr, c.interface, c.valid_secs, c.usable, c.manual
                        );
                    }
                }
                Err(e) => println!("  failed: {e}"),
            }
        }
        println!("global IPv6, best first:");
        for g in global_ipv6() {
            println!("  {} (interface {}, valid for {:?})", g.addr, g.interface, g.valid_for);
        }
        println!("MACs, best first:");
        for m in local_macs() {
            let mac = m.mac.map(|b| format!("{b:02x}")).join(":");
            let nets: Vec<String> = m
                .networks
                .iter()
                .map(|n| format!("{}/{} (broadcast {})", n.addr, n.prefix_len, n.broadcast()))
                .collect();
            let kind = if m.virtual_adapter { "virtual" } else { "real" };
            println!("  {mac}  {}  [{kind}]  {}", m.name, nets.join(", "));
        }
    }
}
