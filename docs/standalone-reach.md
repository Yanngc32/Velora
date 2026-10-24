# Reaching your PC from anywhere: standalone reach

The long form of the README section
[Reaching this PC from anywhere](../README.md#reaching-this-pc-from-anywhere): setup for each
situation, headless and VPS hosts, troubleshooting, security and privacy, limits and a FAQ.
How it was designed is in [nat-traversal.md](nat-traversal.md).

Velora connects over QUIC on UDP port 7420. From another network, a device needs an address that
leads to that port on the PC it wants to control (the *home PC* below, though it can be anywhere).
Over a mesh VPN such as Tailscale or Netbird that address is the VPN's, and you need nothing from
this guide. This guide covers the ways Velora can get a device to the PC **without a VPN and
without a server run by the project or by anyone else**; the only machine you may add is a relay PC
or a VPS of your own.

Everything here is optional and off until you turn it on. A connection is authenticated and
encrypted end to end (mutual TLS 1.3, pinned certificates) whichever way it travels, so none of
these ways makes a session weaker, and none of the helpers in between can read it.

> [!NOTE]
> The code is covered by automated tests but has not been through field tests on real networks
> yet. [Status](#status) says what is confirmed and what is not.

**On this page:** [The short version](#the-short-version) ·
[Which way to use](#which-way-to-use) · [How a connection is made](#how-a-connection-is-made) ·
[The switches](#the-switches) · [Setting it up](#setting-it-up) ·
[Waking a sleeping PC](#waking-a-sleeping-pc) · [On the command line](#on-the-command-line) ·
[Files](#files) · [Troubleshooting](#troubleshooting) ·
[Security and privacy](#security-and-privacy) · [Limits](#limits) · [Status](#status) ·
[FAQ](#faq) · [How it is built](#how-it-is-built) · [Glossary](#glossary)

## The short version

1. Use Tailscale or Netbird on both computers? Nothing to do.
2. Otherwise open the Velora app on the home PC, turn sharing on, go to **This PC → Reach from
   other networks** and turn on **Reach this PC from other networks without a VPN**.
3. Read the line under the switch:
   - **Port open on the router**: devices can reach this PC at its public address. If your
     provider changes that address now and then, also turn on **Find this PC when its address
     changes**.
   - **The router has not opened a port**: [turn UPnP on or forward the port by
     hand](#a-router-that-does-not-open-ports).
   - **Your internet provider shares this address with other customers, so the router cannot
     open a port**: [CGNAT or a second router](#behind-cgnat-or-two-routers). A
     [relay PC](#a-relay-pc) is the way in that does not depend on that router.
4. Connect once from each device while it can still reach the PC. A device learns the addresses,
   the DHT key and the relays only when it connects.
5. Test from another network: a phone on mobile data, not on the home Wi-Fi.

## Which way to use

| | Mesh VPN | Standalone reach | Relay PC |
|---|---|---|---|
| **How** | The computers join a private network and Velora uses its addresses | The router forwards a port, the PC lists its public and IPv6 addresses, publishes them in the DHT and opens a hole when asked | Both ends connect out to another PC of yours, which copies their packets |
| **Right when** | You already use one: it is still the easiest | There is no VPN and the PC can be reached some way | The home PC cannot be reached directly (CGNAT, two routers), or you want to wake it from afar |
| **Needs** | The VPN on both sides | UPnP or NAT-PMP on the router, or public IPv6, or NATs that allow a hole punch | A second PC of yours that stays on and can itself be reached, or a VPS |
| **Costs** | What the VPN costs | A little background traffic ([below](#background-traffic)) | The relay PC's internet: the whole picture passes through it |
| **Does not help when** | You cannot install it on one of the computers | Your provider shares the address and the NATs do not allow a punch | The relay PC cannot be reached either |

A mesh VPN keeps working exactly as before: its addresses are in the same race as the others. The
other two are for people who have none. They combine: a PC with a port open on its router needs no
relay; a PC behind CGNAT usually does.

## How a connection is made

When a device connects to a PC it is paired with, it builds a list of ways in and tries them in
this order. The first handshake that completes wins and the others are dropped.

| When | What is tried |
|---|---|
| At once | The addresses stored for the PC, as it last listed them (LAN, VPN, public, IPv6): the main one first, each other one 250 ms after the one before. |
| After 0.5 s, if nothing has connected | The PC's record in the DHT, when the device holds the PC's DHT key and its own secret. Every address and relay in the record joins the race. The lookup is given up after 6 s. |
| After 2 s | Each relay PC the home PC is registered with (a relay's addresses 2 s apart, because a relay serves one client per PC), and a hole punch toward the endpoint in the record when the PC's NAT allows it. |

At home the stored LAN address answers in milliseconds, so nothing else starts: the DHT is never
asked and no relay is bothered. Away from home the order is the order of cost: direct addresses
first, then the DHT, then relays and punches. That is why a connection from afar can take a few
seconds longer than one at home.

**What a device keeps.** Every time a session connects, and when a device pairs, the PC sends its
addresses with their kinds, its DHT key, the secret that opens its record for that device, the
relays it is registered with and the address of its network adapter (for Wake). The device stores
them in `known_hosts.json`. A files-only connection neither asks for this nor stores it. Nothing
reaches a device that cannot connect, so after you change a switch each device has to open a
session once to hear about it.

**Which way won** is shown in three places: **This PC** says *The last connection came in through*
and the kind and address; `velora connect` prints *Connected to 'X' through: Public address · …*;
the host's log has *'Phone' reached this computer at its public address (…)*.

## The switches

All three are on **This PC → Reach from other networks**, off by default, saved in `reach.json` in
the host's [state folder](#files), and each can be on without the others. They need the host
running (sharing on). Under the [Windows service](#the-windows-service) changing them needs an
administrator. They work best together: the public and IPv6 addresses, the punch endpoint and the
relays that the DHT record lists all come from the first switch, so the second one alone publishes
only the PC's LAN and VPN addresses.

**Reach this PC from other networks without a VPN** (`standalone`). While it is on, the host:

- asks the router to forward its UDP port to this PC, NAT-PMP first, then UPnP (3 s to find the
  router, 5 s per protocol). The lease is one hour and is renewed every 30 minutes. When the host
  stops normally it removes the mapping, if the router shows that it holds that port for this PC;
  a router that will not list its mappings, or that holds the port for another computer, keeps it
  until the lease ends. When the router cannot open a port, the host asks again after 1 minute,
  then 2, 4, 8, 16 and every 30 minutes; turning the switch off and on asks at once. If the router
  gives another port than the wanted one (two hosts behind one router), that port is what is
  advertised;
- judges the address the router reports. A private address, or one in 100.64.0.0/10, means a
  second router or CGNAT, and so does a public-looking one that differs from the address DHT nodes
  see this PC at. The mapping is then kept but not advertised. A mapping whose renewal fails is
  withdrawn at once, and a withdrawn address does not come back sooner than a minute later;
- lists one global IPv6 address per network adapter (looked at every minute), if it listens on
  every address, which is the default;
- asks public DHT nodes from its own QUIC socket which `ip:port` they see, to learn what its NAT
  shows to the world and whether it keeps one port per destination. It does so when it starts,
  every 10 minutes, 2 s after its LAN or IPv6 addresses or the address its router mapped change,
  and when a keepalive shows that the NAT now maps the socket somewhere else (see
  [Behind CGNAT](#behind-cgnat-or-two-routers));
- registers with a relay PC when it has no public address (10 s after start), or at once with
  the relays you listed;
- opens a hole toward a device that asks for one;
- makes each new address prove itself with a QUIC Retry before it spends effort on it.

**Find this PC when its address changes** (`dht`). The host makes a signing key once
(`dht_key.bin`) and publishes a record under it in the Mainline DHT: its addresses, the kind of NAT
it saw, the first relay it is registered with, its adapter address and the time. The record is
sealed separately for each paired device. It is published about 3 s after something it shows
changes (never more than every 15 s), every 30 minutes anyway, and after the PC wakes from sleep;
a failure is retried after 30 s, then 1, 2, 4… up to 10 minutes. A publish counts when at least 8
DHT nodes stored it; the log says how many did. A device appears in the record about 20 s after it
first connects with the switch on, because that is when it is given its secret. With the first
switch on as well and no relay registered, the host looks for punch requests in the DHT, once per
paired device every 45 s (every 8 s for 3 minutes after the device that connected last
disconnects).

**Let my other PCs connect through this one** (`relay_for_others`). The host accepts the
registrations of the computers you allowed and the requests of its paired devices, and copies
packets between them; it also sends magic packets for computers registered with it and passes on
their punch requests. It makes new addresses prove themselves, as above. It remembers the adapter
address and last address of every computer that registered (`relay_known.json`), so a relay PC
that reboots can still wake a PC that was asleep when it did.

## Setting it up

### A router that opens ports

1. Turn sharing on, then **Reach this PC from other networks without a VPN**.
2. Within seconds the router line reads **Port open on the router** ("Opened with UPnP; Velora
   keeps it renewed"), **Public address** lists the address, and the pairing QR code says
   **Reachable from other networks at** that address.
3. Connect once from each device (or pair again) so it stores the address, then test from
   another network.
4. If your provider changes your public IP, also turn on **Find this PC when its address changes**
   and connect once from each device afterwards: a device can then look the new address up in the
   DHT.

Two hosts behind one router both ask for 7420; the second gets another external port and
advertises that one. A laptop that moves to another network gives up the old address at once and
asks the new router. A host started with `--bind` on one specific address (not `0.0.0.0` or
`[::]`) maps nothing: the router would forward to an address the socket may not take packets on
(the log says so).

### A router that does not open ports

The router line reads **The router has not opened a port** and the log says *no router opened UDP
port 7420*. Neither NAT-PMP nor UPnP answered. Many provider routers ship with UPnP off, and
company networks turn it off on purpose.

- Turn UPnP (or NAT-PMP) on in the router, then toggle the Velora switch off and on to ask at once.
- Or forward UDP 7420 to the PC by hand, as before this feature existed. Velora cannot see a port
  you forwarded, so it does not advertise it: pair with the public address (or a DNS name for it)
  so the device stores it.
- If your provider gives the PC a global IPv6 address, **IPv6 address** lists it. Your router's
  IPv6 firewall must let UDP 7420 in to the PC; Velora does not open IPv6 holes (no PCP or
  pinholes).
- Otherwise a [relay PC](#a-relay-pc), or a mesh VPN.

### Behind CGNAT or two routers

The line reads **Your internet provider shares this address with other customers, so the router
cannot open a port** and the log says *the router's external address … is an address the provider
shares between customers (a CGNAT)* or *… a private address (a second router is in front)*. A port
mapped on a router in front of another NAT only reaches that NAT, so Velora does not advertise it.
What is left, in the order it is worth trying:

1. **Public IPv6**, if your provider gives it (see above).
2. **A relay PC**: the home PC connects out to it, so no port has to be opened on the home PC's
   router (not yet confirmed on a real CGNAT, see [Status](#status)).
3. **The DHT and a hole punch.** Turn on both the first switch and **Find this PC when its address
   changes**. The PC pings DHT nodes from its QUIC socket; when its NAT keeps one external port per
   socket it lists that endpoint in its record, and a device asks the PC to open a hole toward the
   device's own endpoint and dials the PC's from the same socket. The request travels over the
   relay link when the PC is registered with a relay PC, and otherwise through the DHT, where the PC
   looks every 45 s, so the device waits up to a minute. It works only when both NATs keep one
   external port per socket; a symmetric NAT on either end (some carrier and company networks)
   rules it out and Velora does not try. To keep that endpoint valid, the host sends a small DHT
   ping every 20 s from the QUIC socket while the record offers it. The answer says where the
   node sees the socket: if that is another endpoint than the one measured (a router that
   restarted, a PC that woke up), the host measures again and the record follows, within about a
   minute. It does so at most once a minute, less often while what the pings see keeps changing,
   and not for an endpoint a measurement did not confirm; the pings go to the nodes that told it
   where it is.
4. **A mesh VPN**, or asking your provider for a public IPv4 address (some do).

With two routers in a row (yours behind the provider's), putting the outer one in bridge mode, so
that only one device does NAT, removes the second NAT.

### A relay PC

A relay PC is another computer of yours that stays on and can be reached from outside. The home PC
and your device both connect **out** to it, so neither has to be reachable, and it copies the
encrypted packets between them:

```
  your phone or laptop ──────▶ relay PC ◀────── home PC
  (paired with both)           (reachable)      (connects out to it)
  └── the session runs end to end between these two ──┘
```

What you need:

- The relay PC runs a Velora with this feature and is on.
- At the relay PC, **Let my other PCs connect through this one** is on, and so is **Reach this PC
  from other networks without a VPN**: the second switch is what asks its router for a port and
  lists its public and IPv6 addresses, which is how a device away learns where the relay is. Its
  card should say **Port open on the router**. A relay that no address reaches is no use; a VPS has
  a public address of its own ([below](#a-vps-as-the-relay)).
- At the home PC, **Reach this PC from other networks without a VPN** is on: it registers only
  while that switch is on.

The steps are the ones **This PC → Relay PCs** shows, on both PCs:

1. Pair your phone or laptop with the relay PC, as usual.
2. On the home PC, under **Relays this PC uses**, paste the relay PC's pairing link and click
   **Use as my relay**. On the relay PC, under **Computers allowed to use this PC as a relay**,
   paste the home PC's link and click **Let it use this PC**. A PC shows its link when you click
   **Show QR code** and then **Copy link**; the home PC's link exists while its pairing window is
   open (10 minutes), which is long enough to copy it. The relay PC never dials the home PC (the
   home PC dials out to it), so this works for a home PC that nobody can reach.
3. Pair your phone or laptop with the home PC, as usual. A device paired before opens a session
   once from home, after the relay shows as registered, to learn where the relay is (with the DHT
   switch on it can also read it from the record).

**Which addresses the link carries.** A pairing link lists the PC's LAN and VPN addresses and its
router-mapped public address, as they were when the pairing window opened. Open **Show QR code** on
the relay PC after its card shows the public address (close it and open it again if the address
came later). The link never carries a global IPv6 address or a port you forwarded by hand: for those,
write the address, or a DNS name, into `relays.json` on the home PC. The home PC dials the
addresses stored for the relay; the devices away are given the relay's own list (public, IPv6,
VPN, LAN) and the address that worked from the home PC.

Check it: on the home PC the relay has a green dot, *Registered: your devices can reach this PC
through it*; on the relay PC the home PC reads *Registered here now*. From another network
`velora connect "Home PC"` should print *through: Another PC of yours (relay) · Relay PC · …*.

Things to know:

- **What happens by itself.** A home PC with the first switch on and no public address also tries
  the computers in its own **Devices** list, 10 s after it starts, and registers with one that
  relays for others and knows this PC: the relay PC must have paired with the home PC from its own
  side or been told to allow it (step 2). One that does not relay, or does not know it, is asked
  again 10 minutes later, so a PC you have just switched to relay can take that long to be found;
  at most 4 such registrations are held at once. The steps above make it immediate, and work for a
  relay PC that is not in that list.
- **A relay you listed is used always**, even when the home PC has a public address of its own; one
  found by itself only while it has none. List the PC that will wake yours (see
  [Waking](#waking-a-sleeping-pc)) for that reason.
- **One device at a time.** A relay carries one client per home PC; a second device that asks
  takes the first over. On one computer, `velora connect`, `velora bench`, the Files page and files
  dropped on the PC's card check first: while a session of this computer holds the relay to that
  PC they refuse, with *'X' is already open on this computer through a relay…: close the other
  window first*, instead of taking it over. A session started later does take an idle file
  connection over, and a transfer running on it is lost.
- **A drop ends the session.** If the home PC's connection to the relay drops, or the device's,
  the relayed session ends and nothing carries it over: the home PC registers again by itself
  (after 5 s, then longer) and the device connects again. A relay address that does not answer
  costs that attempt up to 8 s; the other attempts are not held up.
- **Updates.** A relay PC does not restart for an update while it carries a session; a
  registration with nothing relayed does not hold it back.
- **Bandwidth.** The relay PC receives the whole picture and sends it on: as much upload as the
  session's bitrate (12 Mbit/s at most by default; the app says 6 to 12), and the same in download.
  The bitrate adapts to what that link can carry, which shows as a softer picture, not a failure.
- **Passwords.** An access password on the relay PC protects its own screen. It is not asked of the
  relay links that your devices and your computers make to it, and a device that is paired with
  the relay PC can use its bandwidth without it. The home PC asks for its own password as always,
  inside the end-to-end session.
- **An address that changes.** The home PC dials the addresses stored for the relay when you added
  it (the ones in the link). For a relay PC without a fixed public address, write a DNS name in
  [`relays.json`](#files) instead (`name:7420` is accepted), or add the relay again when its address
  changes. The addresses the home PC tells your devices are the ones the relay reported last.
- **The Windows service.** A relay PC or home PC installed as the lock screen service cannot see
  your user's paired list, which is why the steps above hand the service what it needs through the
  app. It needs an administrator.

### A VPS as the relay

A machine with a public address and no screen can be a relay: `velora-host run --relay-only`
serves relays and nothing else (no capture, no input, every connection is a link). The VPS firewall
or cloud security group must let **UDP 7420** in. This needs no app on the VPS. Unpack the Linux
archive in `/opt/velora`, give the relay a user and a folder of its own, and pair with it as that
user, in that folder: a pairing run without `--config-dir` would write the VPS's identity
somewhere else, the service below would make a new one, and the fingerprints you copy would stop
matching.

```sh
# on the VPS
sudo useradd --system --create-home --home-dir /var/lib/velora velora
sudo -u velora /opt/velora/velora-host --config-dir /var/lib/velora run --relay-only --pair
#   prints a one-time code (10 minutes) and keeps running; press Ctrl-C once your laptop has paired
# on your laptop: pair with the VPS like any host
velora pair <vps-address>:7420 VL1-...       # "Paired with 'vps'. This PC only relays connections..."
```

Then the two lists that the app would write, with the fingerprints from your laptop's
`known_hosts.json` (the `fingerprint` field of the VPS and of the home PC, both paired from there).
On the home PC, `relays.json` in its [state folder](#files) (read again every 30 s) names the VPS:

```json
[ { "name": "VPS", "address": "203.0.113.10:7420", "fingerprint": "<the VPS's fingerprint>" } ]
```

On the VPS, `relay_hosts.json` (read at every link), in the same kind of folder (`/var/lib/velora/host`
with the unit below), allows the home PC:

```json
[ { "name": "Home PC", "fingerprint": "<the home PC's fingerprint>" } ]
```

The home PC needs **Reach this PC from other networks without a VPN** on. Pairing your phone or
laptop with the home PC is as usual, and a device that was paired before opens a session once from
home, after the home PC has registered, to learn about the VPS.

To keep the relay running, a systemd unit like this one, as an example to adapt (Velora does not
ship a service file yet, and this one has not been run by the project). It uses the user and the
folder from above:

```ini
[Unit]
Description=Velora relay
After=network-online.target
Wants=network-online.target

[Service]
User=velora
StateDirectory=velora
ExecStart=/opt/velora/velora-host --no-update --config-dir /var/lib/velora run --relay-only
Restart=always

[Install]
WantedBy=multi-user.target
```

Drop `--no-update` if the user can write to the install folder and you want the relay to update
itself. A VPS carries every relayed picture, so mind its bandwidth quota. It cannot wake a PC: a
magic packet only works on the sleeping PC's own network.

### The Windows service

With **This PC → Access on the lock screen** (or `velora-host service install`) the host runs as
the `Velora` service, as SYSTEM, with its state in `C:\ProgramData\Velora\host` and its log in
`C:\ProgramData\Velora\host\host.log`. For standalone reach that means:

- Changing the three switches, the relay lists and the allowed computers needs administrator
  rights. Otherwise the app says *Only an administrator can change this, because Velora runs as a
  Windows service on this PC*: open Velora as administrator (right-click, **Run as
  administrator**) and try again.
- When the service is installed it brings over from your own host the identity, the paired
  devices and the access password, and the reach settings: the switches, the DHT key and the
  devices' secrets, and the relay lists (a service that already has an identity keeps what it has).
  Look at **This PC** after installing it all the same.
- It adds its own firewall rule, **Velora (service)**: inbound UDP 7420 for the installed program,
  on every network profile. A service never gets Windows' "allow access" prompt.
- Without the service, if Windows asks whether to allow `velora-host`, choose **Allow**.

### Linux and other headless hosts

A host without the app keeps everything in its state folder (`~/.config/velora/host` on Linux, or
under `--config-dir`). The switches are read when the host starts, so write `reach.json` first:

```sh
mkdir -p ~/.config/velora/host
cat > ~/.config/velora/host/reach.json <<'EOF'
{ "standalone": true, "dht": true, "relay_for_others": false }
EOF
velora-host run
```

Missing keys are off. There is no `velora-host` command that changes the switches: the app does it
over the host's control channel (a named pipe on Windows, a Unix socket elsewhere, open only to the
user the host serves), so a host without the app is set by this file. The log goes to the terminal
(`RUST_LOG=info,velora_host=debug` for more; the DHT library is kept to its errors unless
`RUST_LOG` names `mainline`). If a firewall runs on the machine, let UDP 7420 in
(`sudo ufw allow 7420/udp`). The host binds `[::]:7420`, which takes IPv4 and IPv6;
`--bind 0.0.0.0:7420` is IPv4 only, and a machine that cannot do dual-stack gets IPv4
automatically. The Linux host needs an X11 session as before; `--relay-only` does not.

### From a phone

The Android app shares the connection code of the computer client, so it uses stored addresses, the
DHT and relays in the same order. It learns them like any device, by connecting once where the PC
can be reached (pairing counts). It needs no new Android permission (`INTERNET` is enough). It has
no Wake button yet, and this part has not been run on a phone ([Status](#status)). Some mobile
networks have IPv6 only; the DHT and hole punching use IPv4.

## Waking a sleeping PC

A sleeping PC publishes nothing and answers nothing, so waking comes first. The **Wake** button on
the PC's card (or `velora wake`) sends a Wake-on-LAN *magic packet*: six bytes of `FF` and then the
PC's adapter address sixteen times, as a UDP broadcast on ports 9 and 7, to the network's broadcast
address and to 255.255.255.255. Whether the PC wakes is decided by its hardware and Windows, which
Velora cannot see. Check, on the sleeping PC:

| Layer | Setting |
|---|---|
| Firmware (BIOS/UEFI) | Wake on LAN (or PCI-E wake) on. To wake a PC that is switched off rather than asleep, also turn off the "deep sleep" / ErP / EuP power saving that cuts power to the adapter. |
| Windows | Device Manager → the network adapter → Power Management: allow the device to wake the computer, and only a magic packet; Advanced: Wake on Magic Packet on. Control Panel → Power Options → *Choose what the power buttons do* → turn **fast startup** off. |
| The link | Wired Ethernet. Waking over Wi-Fi depends on the adapter and is often unsupported. |
| Velora | Connect to the PC once while it is on, with a recent Velora on both sides, so your device knows its adapter address (the host sends it when you connect). |

**Asleep versus off.** Sleep and hibernate are the easy cases: the adapter can stay powered and
listen. A PC that is shut down only wakes if the firmware keeps the adapter powered, and Windows'
fast startup can interfere. Laptops with Modern Standby vary by model. On Windows, while sharing is
on, Velora keeps the PC from sleeping by itself (**Keep this PC awake**, on by default; elsewhere
it holds nothing), so Wake matters for a PC you shut down or put to sleep, for a closed laptop lid,
and when sharing is off.

**Who can send the packet.** It has to start on the sleeping PC's own network; a router drops a
magic packet that comes in from the internet (it forgets the sleeping PC's ARP entry and refuses
broadcast forwarding). Velora tries, in this order:

1. **Your device itself**, when one of its networks holds one of the addresses the PC listed as LAN:
   a laptop on the home Ethernet, a phone on the home Wi-Fi.
2. **A relay PC** the home PC is registered with. The device asks it, over a link, to send the
   packet on its own network. The relay PC must be on, must be on the same network as the sleeping
   PC, and must have **Let my other PCs connect through this one** on. It remembers the PC's
   adapter address and last address from when it registered, even after the PC went to sleep or the
   relay PC rebooted.
3. Nobody: the app says *You are not on this PC's network, and none of your PCs there could send
   the signal*.

> [!IMPORTANT]
> **To wake a PC from outside the home network you need another PC at home that stays on and can be
> reached from outside** (a port open on its router, IPv6 or a VPN address), registered with the
> home PC under *Relays this PC uses*. A VPS cannot do it, because it is not on that network, and
> neither can a relay at home when nothing at home can be reached from outside. A home behind
> CGNAT with no IPv6 and no VPN has no way to wake its PC from afar. From inside the home network
> (your device on its LAN or Wi-Fi) none of this is needed.

**In the app** the Wake chip reads *Waking…* while it works, and the answer shows as a bubble under
the card for 12 s; the chip rests for 5 s after an outcome, because a relay lets a device start only
so many requests (6 at once, then one every 5 s).

**After *Wake-up signal sent*.** The packet left; the PC needs from several seconds to a minute or
more to come up and publish again, and the host redoes its mapping and its DHT record at once after
waking. Try
`connect` no faster than once every 5 s: a relay lets a device start 6 requests at once and then one
every 5 s, shared by registering, relaying, waking and punching. If you are on another network that
uses the same address range as home (192.168.1.x is common), Velora believes you are home, sends
the packet there and says *Wake-up signal sent* while nothing wakes.

## On the command line

```sh
velora wake <host-name>          # name or address, as for connect
velora connect <host-name>       # says which way in it took
velora bench <host-name>         # starts with the same line, and the picture size
velora-host run --relay-only     # relays only: no screen, no input
```

**`velora wake`** prints the app's words, in the system language (Portuguese or English). Exit
status 0 only when the
signal was sent (*Wake-up signal sent. The PC can take a minute to start…*). Exit status 1, on
standard error: *You are not on this PC's network, and none of your PCs there could send the
signal…*, *This PC has not told Velora how to wake it. Connect to it once while it is on…*, or
*Could not send the wake-up signal: …* (for example `'x' is not paired yet`).

**`velora connect`** prints one line before the window opens, in the app's words and form (a label,
a middle dot and the address), such as `Connected to 'Home PC' through: Local network ·
192.0.2.10:7420`; `velora bench` starts with the same line and the picture size after it. In
Portuguese it reads *Conectado a 'Home PC' por: Rede local · …*.

| What follows *through:* | The way in |
|---|---|
| Local network · address | A LAN address |
| VPN · address | A mesh VPN address |
| Public address · address | A mapped or forwarded port |
| IPv6 address · address | A global IPv6 address |
| Another PC of yours (relay) · name · address | A relay PC, named after the computer you paired with |
| Direct through the routers (hole punch) · endpoint | A hole punch |
| Another route · address | An address of a kind this version does not know |

A host started with `--relay-only` has no screen: `connect` and `bench` end with *This PC only
relays connections: there is no screen to show.* (status 1), and `pair` pairs all the same and says
so (status 0), because pairing is how a device gets to use the relay. A second `velora connect` for a
PC that is open on this computer through a relay is refused: *'X' is already open on this computer
through a relay, which carries one connection to a host at a time: close the other window first.*

**`velora-host run`** takes, besides the usual options: `--bind ADDRESS:PORT` (default `[::]:7420`),
`--relay-only`, `--pair`, and the global `--config-dir DIR` and `--no-update`. `RUST_LOG` sets the
log level for both programs; the DHT library (`mainline`) is kept to its errors unless `RUST_LOG`
mentions it, because on Windows it would otherwise log about 17 warnings a second while idle.

## Files

`<config>` is `~/.config/velora` on Linux, `%APPDATA%\velora\config` on Windows,
`C:\ProgramData\Velora` for the Windows service, or the folder of `--config-dir`. The host keeps its
state in `<config>/host`, the client in `<config>/client`. Files the app and the host write for you
are listed so you can find them; edit the ones marked *by hand* only when the host is stopped or as
described.

| File | In | Holds |
|---|---|---|
| `reach.json` | host | The three switches `standalone`, `relay_for_others`, `dht`. Written by the app; **by hand** for a headless host, before it starts. |
| `relays.json` | host | Relay PCs this PC registers with: `[{ "name", "address", "also": [], "fingerprint" }]`, the shape of an entry of `known_hosts.json`. Written by **Use as my relay** (also under the service, by an administrator); by hand on a host that has no app. A relay-only VPS never registers with a relay, so this file belongs on the home PC. Addresses are `ip:port` or `name:port`; at most 16 relays. Read every 30 s. A file that cannot be read is refused, not overwritten (*relays.json cannot be read; fix or remove it*). |
| `relay_hosts.json` | host | Computers allowed to register here: `[{ "name", "fingerprint" }]`. Written by **Let it use this PC**; at most 64 computers. Read at every link. |
| `relay_known.json` | host | Computers this relay can wake: fingerprint, adapter address, last address. Written by the host. |
| `dht_key.bin` | host | The 32-byte seed of the key the record is published under. Made once, never replaced. Every paired device holds its public half, so deleting it makes devices lose the record until they connect again. |
| `reach_secrets.json` | host | The secret of each paired device (and a shared one) that opens the record. Written by the host. |
| `dht_cache.txt` | host and client | The DHT routing table and the last sequence number used, so the next start is quick (a text file headed `velora-dht-cache 1`: a line per saved node and per key). |
| `host.log` | host | The log, when the app or the service started the host. |
| `known_hosts.json` | client | The paired computers. With reach it also keeps, for each, the kinds of its addresses, its DHT key and secret, its relays and its adapter address. |
| `relay-<fingerprint>.lock` | client | An empty file that stops a second window from taking over a relay; one per PC ever reached through a relay. Leave it. |

The fingerprint in these files is the base64url text of the SHA-256 of the computer's certificate,
43 characters: copy it from the `fingerprint` field of the computer's entry in a paired device's
`known_hosts.json`.

## Troubleshooting

Look in the host's log (`host.log`, or the terminal) for lines about the mapping, the record and
the relays; for the client's side run `velora connect` in a terminal with
`RUST_LOG=info,velora_client_core=debug`. Log lines are quoted from their start.

| You see | It means | What to do |
|---|---|---|
| No **Reach from other networks** card on This PC | The host is not running or predates this feature | Turn sharing on; update Velora on this PC (the program that shares it) |
| **The router has not opened a port**; log *no router opened UDP port 7420* | The router answered neither NAT-PMP nor UPnP | Turn UPnP on or forward the port by hand; toggle the switch to ask at once ([details](#a-router-that-does-not-open-ports)) |
| Log *the host is bound to …, not to every address: no port is mapped* | The host was started with `--bind` on one specific address | Bind to every address (the default), or forward the port by hand |
| **Your internet provider shares this address…**; log *the router's external address … is an address the provider shares* / *… a private address (a second router is in front)* / *the router says its external address is …, but the DHT nodes see this PC at …* | CGNAT, or another NAT in front of the router | [Behind CGNAT or two routers](#behind-cgnat-or-two-routers) |
| **Port open**, but a device away cannot connect | The device does not have the address, a firewall or the provider blocks inbound UDP, or the router maps to another PC | Connect once at home so the device stores the address; check Windows Firewall (rule *Velora*, UDP 7420); test from mobile data, not from the home Wi-Fi (a test from inside often fails through the router even when it works from outside). The log shows *'Phone' reached this computer at its public address (…)* when it works |
| No *published the host's record in the DHT for N devices (seq …, kept by N nodes)* line | Nothing to publish yet: no address, or no paired device holds a secret | Connect once from each device with the switch on; the line appears about 20 s later |
| *could not publish the host's record in the DHT (…); trying again in …* | Offline, or UDP blocked | Check the network; the host retries by itself. A publish counts when at least 8 nodes stored it |
| Client debug: *the host has no record in the DHT* | The host has not published, or the lookup came back empty | Wait a minute and retry; a cold start sometimes asks only the bootstrap nodes and hears nothing |
| Client debug: *the host's record does not open with this device's secret* | The device was removed from the host, or its secret is stale | Pair again; with more than 11 devices all share one secret, which changes when one is removed |
| No DHT line at all in the client's debug output | The device holds no DHT key and secret for the PC yet, so it does not even look: it has not opened a session since the DHT switch was turned on | Open a session once where the PC can be reached |
| Client info: *the host's record in the DHT lists N addresses and M relays, K ways in*, then *connected through …* | It worked | Nothing |
| Client debug *the host's record is N hours from the clock: not read*; host log *the punch request is dated N s ahead of this clock…* or *… is N s old, at most 60 s are served* | A clock is wrong: a device ignores a record more than a day from its own clock, and the host refuses a punch request dated more than 10 s ahead of its clock or older than 60 s | Set both computers to automatic time |
| Log *the NAT shows this computer as … (endpoint-independent NAT)* | The NAT keeps one port per socket: the record lists that endpoint and a punch can use it | Nothing |
| Log *the NAT shows this computer as … (dependent NAT)* | The NAT picks a port per destination (symmetric): no punch | Use a relay PC |
| Log *the NAT shows this computer at …, which is not an internet address* | Another NAT is in front of this one | [Behind CGNAT or two routers](#behind-cgnat-or-two-routers) |
| Log *a DHT node sees this computer at … now: measuring again* | A keepalive's answer showed that the NAT now maps the QUIC socket elsewhere (a router restart, a wake) | Nothing: the host measures again and the record follows within about a minute |
| Home PC's relay has a grey dot, **Not registered: it refused this host: this device is not paired with the host** | The relay PC has not allowed this PC | On the relay PC, **Let it use this PC** with this PC's link |
| … **Not registered: it does not relay for other devices** | The relay PC's switch is off, or its Velora predates relaying | Turn on **Let my other PCs connect through this one**; update it |
| … **Not registered: standalone reach is off** | The home PC's first switch is off | Turn it on |
| … **Not registered: this computer only relays** | The home PC runs with `--relay-only` | Relays do not register with relays |
| *relay '…' (…): …; trying again in N s* in the log | The reason is in the text. The host retries after 5 s, then doubling up to 5 minutes (with up to 20 % more by chance). A refusal (this PC is not allowed, the PC does not relay, it asks for a password) waits 1 minute for a relay you listed and 10 minutes for a computer found by itself; being replaced by another connection of the same PC, 90 s; being removed by the relay, 10 minutes; the relay stopping, 2 minutes; this PC already holding as many relays as it allows, 1 minute | Fix the reason. Two copies of one host (the same identity on two computers) replace each other |
| A session through a relay ends: `velora connect` prints *disconnected: closed*, and its log says *the relay ended the link: another device took the host over* | A second device asked the same relay for the same PC (a session started later also takes an idle file connection over) | One device at a time per PC through a relay |
| *'X' is already open on this computer through a relay, which carries one connection to a host at a time: close the other window first.* | A session of this computer holds the relay to X, and `velora connect`, the Files page or dropped files will not take it over | Close that window, then try again |
| **Wake**: *You are not on this PC's network, and none of your PCs there could send the signal…* | Not on the PC's network and no registered relay PC there could send | [Waking](#waking-a-sleeping-pc) |
| **Wake**: *This PC has not told Velora how to wake it…* | The PC never told your device its adapter address | Open a session once while it is on, with a recent Velora on both sides |
| **Wake**: *Wake-up signal sent…*, and nothing happens | Firmware or Windows settings, or the same-address-range case | The table under [Waking](#waking-a-sleeping-pc) |
| *Only an administrator can change this…* | The host runs as the Windows service | Open Velora as administrator |
| *relays.json cannot be read; fix or remove it* (or the same for `relay_hosts.json`) | The file was edited by hand and is not valid JSON | Fix it or remove it |
| *This PC only relays connections: there is no screen to show.* | You connected to a `--relay-only` host | Expected; use it as a relay PC |
| A Windows Firewall prompt for `velora-host` | A program with no rule opened a socket | Choose **Allow** |

## Security and privacy

**An exposed port.** With a router mapping, or a port you forward, the host accepts UDP from the
whole internet on its port. QUIC drops anything that is not a valid handshake for the host's
certificate before any Velora code sees it. While the host is exposed (standalone reach on, or
relaying for others, `--relay-only` included) a connection from an address that has not proved
itself is also asked to (QUIC Retry), which costs one round trip and means a forged first packet
cannot make the host send more than it received. Connections that come through a relay are exempt:
the relay's own connection is authenticated. The access password stays a second layer.

**IPv6.** The host listens on IPv6 as well as IPv4 by default, and that stays. The consequence: if
your provider gives the PC a global IPv6 address and your router's IPv6 firewall lets inbound UDP
through, the port is open to the internet over IPv6 **whatever the switches say**, just as a port
you forward is over IPv4, and Retry is used only while a switch that exposes the host is on.
What stands between that port and a stranger is the same as everywhere: anything that is not a
valid handshake with a paired device's certificate is dropped, and the optional password. A host
you start by hand can be kept to IPv4 with `--bind 0.0.0.0:7420`; the app and the Windows service
start it with the default.

**The DHT record.** It is signed with an Ed25519 key of its own (a second key beside the TLS
identity, so no fingerprint changes and nobody has to pair again) and encrypted separately for each
paired device with ChaCha20-Poly1305, under a secret that only the host and that device hold. Nobody
else can read the addresses, and anyone can check that the record is the host's. A fake record
could only point a device at a wrong address, where the TLS handshake would fail.

**What the DHT sees.** The nodes that store or serve the record see the IP address of whoever
publishes and of whoever looks it up, the key, the times of the publishes and, from the size of
the record, roughly how many devices can read it. They do not see an address, a name or a
fingerprint. A device looks the record up only when the addresses it stored did not answer within
half a second.

Punch requests are separate items, each under a key derived from one device's secret. With the
first two switches on and no relay registered, the nodes see the IP address of the host looking
those keys up (once per paired device every 45 s) and, when a device is punching, the IP address of
that device publishing there, and when. The key says nothing about who is who.

**Revoking a device.** A removed device is left out at the next publish (within about 15 s when you
remove it in the app, within a minute with `velora-host revoke`) and can no longer open new
records. It can still read the last record it fetched, and DHT nodes keep an item for hours, so
it may read the addresses in it for that long. It cannot connect: the host checks its paired list
on every connection. With more than 11 paired devices all of them share one secret, and removing
any device changes it for the others, which then cannot read the record until they open a session
once by another route. Pairing the 12th device does the same to the first eleven. When the last
paired device is removed, nothing more is published, and the old record stays in the DHT until
it expires, which takes hours.

**A relay PC** copies QUIC packets between two authenticated connections and cannot read or change
what is inside, because the TLS session runs between your device and the home PC. It forwards only
for devices on its paired list (and lets a computer you allowed register, and nothing else),
limits each device to 6 new flows at once and one more every 5 s, and sees the sizes and timing of
the packets and the IP addresses of both ends.

**Third parties.** Standalone reach contacts, with your IP address visible to them as with any
BitTorrent client, the public bootstrap nodes of the Mainline DHT (`router.bittorrent.com`,
`dht.transmissionbt.com`, `dht.libtorrent.org`, `relay.pkarr.org`) and the nodes they lead to; and,
only as a fallback when a device hole-punches and fewer than two DHT nodes answer, the public STUN
servers `stun.l.google.com` and `stun.cloudflare.com`. The DHT client never serves: it answers
nobody and stores nobody's items. Nothing else leaves the computer, and nothing is reported to
anyone.

**What is in the link and the QR code.** The router-mapped public address appears in the pairing
link, and it and the IPv6 addresses appear on **This PC** and go to every device that connects, as
the LAN address does: you decide who sees the link. A pairing link also
carries the host's DHT key and the secret for the device that pairs with it: whoever holds that
secret can read the host's addresses in the DHT until the device is removed, though it cannot
connect without being paired.

### Background traffic

The datagram counts are from the spike on one home connection ([dht-spike.md](dht-spike.md) §8),
not byte counts; the keepalive's volume is worked out from the size of its ping (65 bytes) and its
rate.

- An idle DHT node exchanges about 50 datagrams a minute (25 each way); a lookup from a fresh node
  about 500; a publish from a fresh node about 1,000. The host publishes every 30 minutes, and
  sooner only when something its record shows changes.
- With the first two switches on and no relay registered, the host looks for punch requests:
  about 2 datagrams a second for each paired device.
- While it advertises a punch endpoint, the host sends one DHT ping every 20 s to keep its NAT
  mapping open: 3 a minute, about 0.3 MB a day each way. A remap that a ping shows costs one
  measurement round (a few datagrams) and one publish, at most one a minute.
- Nothing of this runs while the switches are off.

## Limits

- **A way in must exist.** Velora needs the home PC to be reachable some way: a mapped or
  forwarded port, public IPv6, a hole punch, or a relay PC you own. A mesh VPN is the other way.
- **Hole punching needs well-behaved NATs.** It works when both NATs keep one external port per
  socket (endpoint-independent mapping). A symmetric NAT on either end (some carrier and company
  networks) rules it out, and Velora does not try; use a relay PC.
- **The DHT is IPv4 only** and needs outbound UDP. A network that blocks UDP, or has IPv4 only
  through a translator, may get no DHT; the stored addresses are then all a device has.
- **One client at a time** per home PC through a relay, and one punch at a time per device and PC
  through the DHT.
- **The relay PC carries all of the video.** It needs as much upload as the session's bitrate, and
  the same in download.
- **An access password on the relay PC** protects its screen and is not asked of the links made
  to it.
- **Records.** A record lists at most 1 LAN, 2 VPN, 1 public (or punch), 2 IPv6 addresses and 1
  relay; up to 11 paired devices have a secret of their own, more share one (pairing the 12th, or
  removing any, then locks the others out of the record until they open a session again). A removed
  device can read the last record for hours.
- **Wake** needs a sender on the sleeping PC's own network. From outside the home network that is
  another PC at home that stays on and can itself be reached from outside; a home with none (CGNAT,
  no IPv6, no VPN) cannot wake its PC from afar (see [Waking](#waking-a-sleeping-pc)).
- **IPv6 holes** are not opened (no PCP, no pinholes); the router's IPv6 firewall is yours to set.
  On Windows Velora lists the global IPv6 addresses the system configured by itself: not one typed
  in by hand, a deprecated or tentative one, or a tunnel's (Teredo, 6to4, ISATAP).
- **The first connection through the DHT can take a few seconds**, because the stored addresses are
  tried first.
- **Pairing needs a direct path.** A new device pairs where the PC can be reached directly: at home,
  over a VPN, or at its public address. A punched or relayed pairing is not implemented.
- **Two hosts behind one router** each get their own external port; a host bound to one specific
  address maps nothing.
- **A device and a host behind the same NAT** are not handled by the punch (the NAT's own address is
  what both would dial); on the same network the LAN address answers first anyway.

### Known gaps

Missing, as opposed to limits of the approach:

- **The Android app has no Wake button.** The shared library can send the packet (and ask a relay
  to), but nothing in the app calls it. Its device list does not show the kinds of address a
  computer has either.
- **No pairing through a relay or a punch**: a new device pairs where the PC can be reached
  directly.
- **No IPv6 holes**: no PCP and no pinholes, so the router's IPv6 firewall is yours to set.
- **A relay serves one device per home PC at a time.** The relay framing carries no flow id.
- **The Files page does not hold a relay in turn**: it waits for a session that holds the relay,
  but a session started later takes an idle file connection over, and a transfer running on it is
  lost.
- **The host does not know a connection was a punch**: *The last connection came in through* and
  the host's log call it the public address (the device's own `velora connect` line says it was a
  hole punch).
- **A NAT that could not be classified** (too few DHT nodes told the host where it is: *unknown
  NAT*) is not offered for a punch until the next measurement, up to 10 minutes later.
- **The DHT and the punch are IPv4 only.**

## Status

> [!NOTE]
> Written before any field test. This section is updated once they have been run: routers with
> and without UPnP, the DHT after an IP change, a relay across networks, hole punching on three
> networks.

<!-- STATUS: update after the field tests I1 to I4 of nat-traversal-tickets.md -->

**What the automated tests cover.** Each part has its own tests, none of which touches a real
router or carrier:

- the router mapping against fake NAT-PMP and UPnP routers on loopback, driven through the real
  protocol libraries, with timeouts, conflicts, renewals and removals;
- NAT behaviour against a simulator (endpoint-independent and dependent mapping, filtering,
  mappings that expire when nothing leaves, a NAT that forgets its mapping as a router does when
  it restarts), including a hole punch that completes only because of the keepalive and a record
  that follows a restarted NAT to its new port;
- the DHT record, its sealing and the node, on a local test network of `mainline` nodes;
- the relay: three QUIC endpoints on loopback running a whole Velora handshake and a megabyte through
  the relay with 1% synthetic loss, and across legs of different packet sizes;
- a real session over IPv4 and IPv6 to one dual-stack socket, with the welcome, `Reach` and video;
- the app's cards drawn with fake statuses, the control requests, and the command line.

**Tried by hand on the public Mainline DHT, from one home connection:** publishing a record and
reading it back from a second process and from a second process behind another NAT layer; an item
survived at least 4.5 hours after one publish; the first value of a lookup came back in about half
a second from a saved routing table ([dht-spike.md](dht-spike.md)).

**Still to be confirmed on real networks:** routers that answer UPnP or NAT-PMP and routers that
do not; a real change of public IP with a device away; a relay PC between two networks, with
real video and Wake; hole punching across NATs of different kinds, and what a real router restart
or a wake does to the endpoint (the host should notice within about a minute); the Android app on
mobile data.
Everything was developed and tested on Windows: Linux hosts and the Android app have not been
exercised with these features. No claim about how often a way in works, or how fast a relayed or
punched session is, is made here.

## FAQ

**Do I still need Tailscale?** No. If you already use it, keep it: it is still the easiest way
and Velora uses its addresses in the same race.

**Does it need an account or a server?** No account, and no server run by the project or by anyone
else. A relay PC or a VPS is a machine of yours, and optional. The public DHT and, as a last
fallback, two public STUN servers are third parties ([Security and privacy](#security-and-privacy)).

**Is it safe to open a port?** It is the same port a hand-made forward opens. Anything that is not a
valid handshake for the host's certificate is dropped before Velora sees it, new addresses must
prove themselves, and every device must be paired, with the optional password on top.

**My router has no UPnP. Now what?** Turn it on, forward UDP 7420 by hand, use IPv6 if you have
it, or set up a [relay PC](#a-relay-pc).

**The card says my provider shares the address. Is Velora useless here?** No: a relay PC, a hole
punch (when the NATs allow it) and IPv6 do not need a port on that router. Whether one works on a
given connection depends on the provider and the router; the card and the log tell you what
Velora found.

**Can my phone be the relay?** No. A relay is a computer running `velora-host`.

**Does the relay PC have to stay on?** Yes, while you use it. Any PC of yours that is on and
reachable will do, or a VPS.

**Can two devices use one relay at the same time?** Not for the same home PC: a relay carries one
client per PC, and a second one takes the first over. Different home PCs are independent.

**Can the relay PC see my screen?** No. It sees ciphertext, packet sizes and timing, and the two
IP addresses.

**Can I pair from another network?** Only where the PC can be reached directly (its public address
or IPv6, a VPN). Pairing through a relay or a punch is not implemented.

**Why does connecting from afar take longer?** The stored addresses are tried first, then the DHT
after half a second, then relays and punches after two seconds
([How a connection is made](#how-a-connection-is-made)).

**What if my public IP changes?** Turn on **Reach this PC from other networks without a VPN** and
**Find this PC when its address changes**, and open a session once from each device afterwards. Or
give the home connection a DNS name and pair with it.

**Which ports does it use?** UDP 7420 for sessions (inbound, on the home PC and on a relay PC);
towards the router, UDP 5351 for NAT-PMP, and for UPnP a multicast search on UDP 1900 and then
HTTP to the router; outbound UDP for the DHT (its socket takes port 6881 when that is free,
otherwise any free port, and it sends to the nodes' own ports) and, as a fallback, for STUN (19302
and 3478); UDP 9 and 7 as a broadcast on the LAN for Wake. The host's measurements of its NAT and
its 20 s keepalive pings leave from the QUIC socket (7420), not from the DHT's.

**Does it work with the access password?** Yes. The home PC asks for its own password inside the
session as always. A relay PC's password is not asked of the relay links.

**Does it slow down use on the LAN?** No. The LAN address is tried first and answers before
anything else starts.

**Does it change anything when it is off?** Not for how you use Velora: with the switches off the
host asks the router for nothing, publishes nothing and relays nothing. It does listen on IPv6 as
well as IPv4 by default (see [Security and privacy](#security-and-privacy); a host started by hand
can use `--bind 0.0.0.0:7420` to stay IPv4 only).

## How it is built

<details>
<summary><b>For developers: protocol, formats and where the code is</b></summary>
<br>

A map for people who change the code. The doc comments and tests in the code are authoritative;
[nat-traversal.md](nat-traversal.md) is the design record (with §14 and §15 on what the building
found and changed) and [nat-traversal-tickets.md](nat-traversal-tickets.md) the list of tickets the
work was split into.

**Crates.**

| Where | What |
|---|---|
| `crates/nat` (`velora-nat`) | `mapping` (NAT-PMP, then UPnP), `addresses` (classify addresses, global IPv6, local adapters and their MACs), `observe` (ask DHT nodes or STUN what endpoint a socket shows; NAT kind), `wake` |
| `crates/dht` (`velora-dht`) | `keys`, `record`, `seal`, `node` (publish, resolve, cache), `punch_item` |
| `crates/relay` (`velora-relay`) | `frame` (relay framing), `forward` (the forwarding core) |
| `crates/protocol` | The new messages, the pairing link, the control requests, `KnownHost` |
| `crates/host/src/reach/` | `mod` (state, switches, tasks), `socket` (multiplexer), `mapping`, `dht`, `secrets`, `relay`, `punch`, `poll`, `wake` |
| `crates/client-core/src/reach/` | `mod` (the race), `dht`, `relay`, `punch` |
| `crates/client` | The cards (`gui/reach.rs`), `velora wake` and the route line (`main.rs`) |
| `crates/mobile` | `wake` and the kinds of a computer's addresses, for the Android app |

**Protocol.** The hello's extension flags get `reach` (bit 5); bit 7 means another flags byte
follows (read and skipped, never set). After the welcome, a host sends `HostMsg::Reach` (tag 6)
only to a client that set the bit: addresses with kinds (LAN, VPN, public, IPv6, relay; at most 16),
the DHT key (32 bytes), the device's secret (16), the relays (fingerprint and addresses), the
adapter address and whether the host relays. All zeros for key and secret mean "none". The welcome
keeps 8 plain addresses, relays left out, because a client from before reads exactly 8. Further
host messages: `RelayStatus` (7), `PunchRequest` (8). Client messages: `Reached` (11),
`RelayRegister` (12), `RelayTo` (13), `Wake` (14), `PunchRequest` (15); a host that predates them
decodes the tags as unsupported and ignores them. Lists are capped (16 addresses, 8 relays of 16
addresses each) and cut, never an error, and an `AddressKind` added later must carry no payload,
because this version cannot skip one. The pairing link gains `key=` and `secret=` (78 characters),
so, once the host has a DHT key, a link is cut to 300 characters, what a QR code reads well: the
public address first, then the VPN addresses, IPv6 ones last; the rest reaches the device in
`Reach`. The app talks to the host with `Request::SetReach`, `AddRelay`, `RemoveRelay`,
`AllowRelayHost` and `RemoveRelayHost`, and reads `Status.reach`.

**Links.** A hello with `files_only` and `reach` (and every connection to a `--relay-only` host)
is a *link*: its welcome is 0 by 0 with no features, there is no capture, no session, nobody sent
away, and no access-password question for a device the host knows. `RelayRegister` and `RelayTo`,
which make the connection's datagrams the relay's, are accepted only on links; `Wake` and
`PunchRequest` are answered anywhere. A registering host dials with its *host* identity; the relay
lets in a computer listed in `relay_hosts.json` or in its own client-side `known_hosts.json` for
`RelayRegister` and nothing else.

**Routes.** `Session::route()` and `FilesSession::route()` say how a connection was made: a
`RouteKind`, either `Address(AddressKind)` (a relay is one, with its fingerprint) or `Punch`. The
host still hears only the address (`ClientMsg::Reached`), so for the host a punch is the public
address and nothing on the wire changed.

**The QUIC socket.** The host's endpoint runs on a multiplexer. Besides ordinary QUIC it carries
*probes* (DHT pings sent from the QUIC port, their replies kept away from quinn) and relay *tunnels*
(the peers behind a relay appear to quinn at synthetic addresses; a full or closed tunnel drops
packets and counts them rather than returning an error, because quinn would end the connection on
one). quinn shows the IPv4 peers of the dual-stack socket as IPv4-mapped IPv6 addresses.

**The record** (salt `velora/1`). `Record { fingerprint, addresses, nat, relays, mac, ts }` in
postcard, sealed as `01 | count | nonce(12) | wrap(48) × count | ChaCha20-Poly1305(record)`, where
each wrap holds a fresh content key under a key derived (HKDF-SHA256) from one device's secret. The
sealed value is at most 996 bytes (BEP 44 caps the bencoded value at 1000, and the length prefix
takes 4), which fits 11 devices beside the largest record; with more, one shared secret has one
wrap. The layout is pinned by `seal::tests::the_wire_format_is_pinned` in `crates/dht/src/seal.rs`
(its vector was cross-checked against an independent implementation); a change of it is a protocol
change, and a record of another `record::VERSION` is ignored by a client that cannot read it.
`seq = max(clock, last + 1)`: an equal `seq` is acknowledged and ignored, a lower one refused.

**The DHT node.** One `Node` is one OS thread and one UDP socket (port 6881 when free). It starts
from up to 16 saved routing-table nodes plus the default names, returns the first valid record of
a lookup (and any with a higher `seq` that comes within 200 ms), counts a put as stored only when at
least 8 nodes acknowledged it, saves its table right after a publish or a lookup, and never serves:
every node carries a request filter that answers nobody. A host's node that has been left alone for
10 minutes is rebuilt before its next use, because its table rots.

**The router mapping.** `velora_nat::mapping` asks NAT-PMP, then UPnP IGD. For UPnP it asks for the
wanted external port with `AddPortMapping` first (`AddAnyPortMapping` only suggests a random one,
which would change the advertised port at every restart), and on a conflict uses
`AddAnyPortMapping` where the router has it, else the next port; port 0 is refused. Removal reads
the router's table (`GetGenericPortMappingEntry`, at most 256 entries: `igd-next` has no query by
port) and deletes only an entry whose internal client and port are this PC's. The host classifies the
external address it is given (public, shared, private) and compares it with what the DHT nodes see.

**Measuring the NAT.** A round pings the DHT's bootstrap nodes from the QUIC socket with a read-only
ping (BEP 43) and reads the address each saw it come from (BEP 42), until three have answered, or two
different ones and 400 ms have passed, or 3 s are up. While any vote names an address on the
internet only those count (a node inside a provider's network may say a private one); any
disagreement among the votes that count is a symmetric NAT. A round that learns nothing is retried
after 30 s, doubling up to 5 minutes. What decides a new round is a signature of the network: the
LAN addresses, the IPv6 addresses and the router's mapped address (the verdict about the mapping is
not in it, or the two tasks would wake each other). A keepalive's answer is compared with the
measured endpoint (the whole of it, port included, and only an address on the internet counts); a
different one starts a round after a gap of 60 s that doubles, up to 10 minutes, while the pings
keep seeing change, and an endpoint a round did not confirm is not asked for again. A round started
that way that learns nothing drops `observed` and `nat`. The pings go to the nodes that voted.

**The punch item** (salt `velora/punch/1`). A device puts `{ endpoint, nonce, ts }`, sealed with the
device secret, under an Ed25519 key derived from that same secret, so the host can compute the key of
every paired device and poll it without any message to carry it. The host accepts a request at most
60 s old and 10 s ahead, serves each nonce once for 10 minutes, rate-limits per device and overall,
and refuses endpoints that are not global unicast. It then sends one QUIC Initial toward the endpoint
from its listening port for 12 s; the device keeps dialing from the socket it measured.

**Relay framing.** Each datagram on a relay leg is `[id_hi, id_lo, shape, payload…]`, with
`shape = (chunk_index << 4) | chunk_count`; an inner packet is one datagram or two halves, reassembled
within 2 s. The host stops the path MTU discovery of a connection that comes through a tunnel at
1350 bytes, so that a full packet fits one datagram (the client's side keeps quinn's defaults). The
tunnel's peer has a synthetic address in `fd00:7e1a::/32`. Per device the relay allows a burst of 6
new flows and one more every 5 s. Close codes `0x20` to `0x24` say why a relay leg ended (replaced,
host gone, taken over, removed, shutdown).

**Lessons from the DHT spike** ([dht-spike.md](dht-spike.md)): `mainline` logs a warning about 17
times a second while idle on Windows (the filter keeps it to errors); `extra_bootstrap` drops the
default nodes; DNS for them is resolved once; of the four default bootstrap names measured, only
two answer a ping with the BEP 42 `ip` field, so an endpoint measurement asks several nodes, ignores
private answers while any public one exists and takes the majority; a refused put looks like a
timeout, so sizes are checked first; it may turn a node into a server after 15 minutes, which the
request filter prevents; the routing table rots in 15 to 20 minutes, so it is saved right after a
lookup.

</details>

## Glossary

| Term | Meaning |
|---|---|
| **NAT** | The router rewrites your private addresses to the public one. It forwards inbound packets only for connections it saw leave. |
| **CGNAT** | Carrier-grade NAT: your provider shares one public address between many customers, so your router has no public address to open a port on. |
| **UPnP, NAT-PMP** | Protocols by which a program asks the router to forward a port. Often a router setting; off on many provider and company routers. |
| **DHT (Mainline)** | The BitTorrent network of millions of nodes. Velora stores a small signed, encrypted record in it so a device can find the PC when its address changes. |
| **STUN** | A public server that tells you which address and port it sees you at. Used only as a fallback by a device that is punching. |
| **Hole punching** | Both ends send packets at each other at the same moment, so each NAT sees outgoing traffic first and lets the reply in. |
| **Symmetric NAT** | A NAT that picks a new external port for every destination, which hole punching cannot predict. |
| **Relay PC** | A computer of yours that stays on and copies the encrypted packets between two ends that both connect out to it. |
| **Link** | A short control connection to a relay or a relay-only host: no screen, no session. |
| **Wake-on-LAN** | A *magic packet* broadcast on the sleeping PC's own network that its network adapter recognises and turns the PC on for. |
