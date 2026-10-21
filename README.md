# Screen Mirroring

Open-source, low-latency remote control for your own computers: view and drive a Windows or
Linux PC from another PC (and, later, from your phone). It is designed around input
responsiveness and a picture that is always current, not around maximum image quality.

> **Status: early MVP.** Desktop host (Windows, Linux/X11) and desktop client work end to end:
> pairing, encrypted streaming, keyboard/mouse/scroll. Mobile clients, hardware encoding and
> NAT traversal are next (see [Roadmap](#roadmap)).

## How it works

```
 host (PC being controlled)                                client (PC / phone)
 ┌────────────────────────────────┐   QUIC (UDP, TLS 1.3)   ┌──────────────────────────────┐
 │ capture  DXGI / X11 SHM+Damage │ ─ video: 1 stream/frame ─▶ decode  ─▶ latest-frame slot │
 │ encode   H.264 (OpenH264)      │ ◀─ acks, keys, buttons ──  (reliable control stream)    │
 │ inject   SendInput / uinput    │ ◀─ pointer moves ───────── (unreliable datagrams)       │
 └────────────────────────────────┘                          └──────────────────────────────┘
```

Latency decisions:

- **Pointer moves are QUIC datagrams.** A lost position is replaced by the next one instead of
  being retransmitted behind newer data. Clicks carry their own position, so they land where
  you saw the cursor even if a move was lost.
- **Keys, buttons and scroll use a reliable stream.** A lost key-up would leave a key stuck. The
  host also tracks everything pressed and releases it when the client disconnects or loses focus.
- **Frames are acknowledged after decoding.** The host keeps at most
  `ceil(RTT / frame interval) + 2` frames in flight. When the network or the client falls behind,
  the host captures fewer frames instead of queuing them, so what you see is never stale.
- **Each frame is its own QUIC stream.** Frames don't block each other in the transport, and the
  client decodes them in order.
- **The cursor is drawn locally.** Your own OS cursor moves with zero network latency. The host
  stream doesn't include its cursor.
- **Capture only on change.** DXGI Desktop Duplication and XDamage wake the pipeline only when
  the screen changes, so an idle desktop costs almost no CPU or bandwidth.
- **Keys are physical (scan codes), not characters.** Shortcuts, games and dead keys behave as on
  a local keyboard. Text is produced by the **host's** keyboard layout, so set it to match your
  physical keyboard (e.g. ABNT2).

Measured on a 4-core cloud VM with host, client and a virtual display on the same machine,
full-screen scrolling text at 1080p (worst case for the software encoder): about 37 fps and
about 26 ms from capture to decoded frame. Hardware encoding is the next big step (see Roadmap).

## Project layout

| Crate | Purpose |
|---|---|
| `crates/protocol` | Wire format, TLS/QUIC configuration with certificate pinning, pairing codes, identity storage |
| `crates/host` (`sm-host`) | Capture, color conversion and encoding, input injection, sessions |
| `crates/client-core` | UI-independent client: connection, input API, decoding. Mobile apps will reuse it through FFI |
| `crates/client` (`sm-client`) | Desktop client (winit + softbuffer) |

## Building

Requirements: Rust 1.88+ and a C/C++ compiler (OpenH264 is built from source by the
`openh264` crate).

```sh
cargo build --release
# binaries: target/release/sm-host, target/release/sm-client
```

Linux runtime requirements:

- Host: an **X11** session (Wayland is not supported yet), plus write access to `/dev/uinput`
  for input injection. Without it the host runs view-only. Example udev rule:

  ```sh
  echo 'KERNEL=="uinput", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput"' \
    | sudo tee /etc/udev/rules.d/60-sm-uinput.rules
  sudo usermod -aG input "$USER"   # then log out and back in
  ```

- Client: `libxkbcommon-x11` (X11) or a Wayland compositor.

## Usage

On the computer to control:

```sh
sm-host run --pair
```

This prints a single-use pairing code, valid for 10 minutes, and the exact command to run on the
other device:

```sh
sm-client pair 192.168.0.10:7420 SM1-...      # first time: pairs, saves the host and connects
sm-client connect <host-name>                 # afterwards
sm-client list                                # paired hosts
sm-client bench <host-name> --seconds 10      # headless throughput/latency check
```

Client shortcuts: **Ctrl+Alt+Shift+F** toggles fullscreen, **Ctrl+Alt+Shift+Q** quits.

Host management:

```sh
sm-host clients                 # paired devices
sm-host revoke <name|fingerprint>
sm-host run --fps 60 --bitrate 12000 --bind 0.0.0.0:7420
```

When a second paired device connects, it takes over the session. Switching from the phone to
the laptop just works.

### Access over the internet

Built-in NAT traversal is not implemented yet. Until then, either:

- use a mesh VPN such as Tailscale or WireGuard and connect to the host's VPN address
  (recommended), or
- forward **UDP** port 7420 on the host's router.

Every connection is authenticated and encrypted either way.

## Security model

- Each device has a long-lived self-signed certificate. There is no CA and no account server.
- The pairing code contains the host's certificate fingerprint and 128 random bits. The client
  pins the fingerprint, so even the first connection can't be intercepted, and proves it knows
  the secret over the encrypted channel. The host then stores the client's fingerprint. Codes
  are single use and expire.
- Every later connection is mutual TLS 1.3. The client checks the pinned host certificate and
  the host checks the client against its paired list.
- Keys and lists are stored in the OS config directory (`~/.config/screen-mirroring` on Linux,
  `%APPDATA%\screen-mirroring\config` on Windows), readable only by the user on Unix.

Windows limitations: input can't reach elevated windows unless `sm-host` runs elevated. The
secure desktop (UAC prompts, lock screen) needs the host to run as a service (planned).

## Roadmap

1. **Hardware encoding.** NVENC / Quick Sync / AMF on Windows (zero-copy from the DXGI texture)
   and VA-API on Linux, with software OpenH264 as fallback.
2. **GPU presentation on the client.** YUV textures and shader conversion/scaling instead of the
   CPU path, plus hardware decoding.
3. **Mobile clients** (Android: Kotlin + MediaCodec, iOS: Swift + VideoToolbox) on top of
   `client-core` via UniFFI. Touch input with trackpad and direct modes.
4. **NAT traversal.** A self-hostable rendezvous server, UDP hole punching, and a relay fallback.
5. Wayland capture (xdg-desktop-portal + PipeWire), multi-monitor selection, cursor shape sync,
   clipboard, audio, relative mouse mode for games, adaptive bitrate.
6. Run as a Windows service and a systemd user service; installers.

## License

MIT, see [LICENSE](LICENSE).

H.264 is covered by patents. Cisco pays the royalties for OpenH264 only when users download
Cisco's prebuilt binary. This project compiles OpenH264 from source, which isn't covered.
Check your situation before distributing binaries. Hardware encoders and AV1 avoid the issue.
