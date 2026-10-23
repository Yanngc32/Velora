<p align="center"><img src="packaging/velora-icon.svg" width="112" alt="Velora"></p>

<h1 align="center">Velora</h1>

<p align="center">
  <b>Your screen. Anywhere.</b><br>
  Open-source, low-latency remote control for your own computers.
</p>

<p align="center">
  <a href="https://github.com/Yanngc32/Velora/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/Yanngc32/Velora?style=flat-square&color=7B4DFF&label=release"></a>
  <a href="https://github.com/Yanngc32/Velora/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Yanngc32/Velora/ci.yml?branch=main&style=flat-square&label=CI"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/github/license/Yanngc32/Velora?style=flat-square&color=4EE1C3"></a>
  <img alt="Windows, Linux and Android" src="https://img.shields.io/badge/platforms-Windows%20%C2%B7%20Linux%20%C2%B7%20Android-1A1B22?style=flat-square">
  <img alt="Built with Rust" src="https://img.shields.io/badge/built%20with-Rust-B7410E?style=flat-square&logo=rust&logoColor=white">
</p>

<p align="center">
  <a href="https://github.com/Yanngc32/Velora/releases/latest"><b>Download</b></a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#features">Features</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#building">Building</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <a href="docs/media/velora-tour.mp4"><img src="docs/media/velora-tour.gif" width="800"
    alt="A file request arrives on the laptop, Accept is clicked, and two transfers finish"></a>
  <br>
  <sub><a href="docs/media/velora-tour.mp4">▶ Watch the full tour (38 s, with sound)</a> ·
  Music: “Happy Beats / Business Moves” by ende.app,
  <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a></sub>
</p>

View and drive a Windows or Linux PC from another PC or from your Android phone. Velora is
designed around input responsiveness and a picture that is always current, not around maximum
image quality.

> [!NOTE]
> **Status: early MVP.** Desktop host (Windows, Linux/X11), desktop client and Android app:
> pairing (QR code on phones), encrypted streaming, keyboard/mouse/touch, hardware encoding
> and decoding, signed auto-updates. iOS and NAT traversal are next (see [Roadmap](#roadmap)).

## Features

<table>
  <tr>
    <td width="33%" valign="top">
      <b>⚡ Low latency by design</b><br>
      QUIC over UDP. Pointer moves are datagrams, frames never queue up, and your own cursor
      is drawn locally.
    </td>
    <td width="33%" valign="top">
      <b>🎮 GPU end to end</b><br>
      NVENC, AMF, Quick Sync or VA-API encoding. On Windows, frames stay on the GPU from
      capture to encoder and from decoder to screen.
    </td>
    <td width="33%" valign="top">
      <b>📶 Adaptive bitrate</b><br>
      When the network falls behind, the bitrate drops to 70%, then climbs back step by step,
      with no keyframe.
    </td>
  </tr>
  <tr>
    <td valign="top">
      <b>🔐 Pair once, no accounts</b><br>
      A single-use code or QR code. Mutual TLS 1.3 with pinned certificates, no account
      server.
    </td>
    <td valign="top">
      <b>📁 Files between computers</b><br>
      Drop files on a device card or use the two-sided file manager, even between two remote
      computers. The receiver asks first.
    </td>
    <td valign="top">
      <b>📋 Shared clipboard</b><br>
      Text and images copied on one computer paste on the other, both ways.
    </td>
  </tr>
  <tr>
    <td valign="top">
      <b>🌍 Anywhere</b><br>
      With Tailscale or Netbird, nothing else is needed: the LAN and VPN addresses race, and
      the first to answer wins.
    </td>
    <td valign="top">
      <b>🔒 Lock screen access</b><br>
      As a Windows service, the host follows the lock screen, UAC prompts and the logon screen,
      and runs from boot.
    </td>
    <td valign="top">
      <b>📱 Android app</b><br>
      A laptop-style trackpad, soft and physical keyboards, and hardware decoding with
      MediaCodec.
    </td>
  </tr>
</table>

### Platforms

|  | Windows | Linux | Android | iOS |
|---|:---:|:---:|:---:|:---:|
| **Share this computer** (host) | ✅ | ✅ X11 | — | — |
| **Control another computer** (client) | ✅ | ✅ | ✅ | planned |

## Quick start

1. **Install** Velora on both devices from the
   [releases page](https://github.com/Yanngc32/Velora/releases/latest) (see
   [Installing](#installing)).
2. **Share:** on the computer to control, open **Velora → This PC**, turn sharing on and
   choose **Show QR code**.
3. **Pair:** on the other computer, paste the code or the `velora://` link under
   **New pairing**. On a phone, tap **Scan QR code**.
4. **Connect:** paired computers are listed under **Devices**, one click away.

## Installing

### Windows

Run `velora-<version>-x86_64-pc-windows-msvc-setup.exe` from the
[releases page](https://github.com/Yanngc32/Velora/releases). It installs for your user, without
administrator rights, into `%LOCALAPPDATA%\Programs\Velora`, and adds Velora to the Start menu
and to Installed apps. At the end it asks once for administrator rights (UAC) to add a Windows
Firewall rule, "Velora", that lets other devices reach the host on UDP port 7420 on any
network, Public ones included; declining leaves sharing reachable only where Windows' own
prompt allowed it.

> [!NOTE]
> The installer is not code-signed, so SmartScreen warns about it the first time: choose
> **More info → Run anyway**.

After an automatic update, Installed apps may still show the version first installed.
Uninstalling removes the app, its firewall rule and its "Start with Windows" entry, but not the
lock screen service: turn **This PC → Access on the lock screen** off first, or run
`velora-host service uninstall` as administrator.

### Windows and Linux archives

Download `velora-<version>-<target>.zip` for Windows or Linux (x86-64). Extract it to a
directory **your user can write to**, so updates can be installed, for example
`%LOCALAPPDATA%\Velora` or `~/.local/share/velora`. The archive contains both `velora-host`
and `velora` and the FFmpeg libraries for hardware encoding.

### Android

Download `velora-<version>-android.apk` from the
[releases page](https://github.com/Yanngc32/Velora/releases) and install it (allow installing
from unknown sources). See [Android](#android-1) for how to use it.

### Updates

Release builds keep themselves up to date:

- `velora-host run` checks one minute after start and then every 6 hours. When it finds a new
  version, it installs it and restarts once nobody is connected and no pairing code is open.
- `velora` checks in the background when it connects. The new version is used the next
  time it starts.
- `velora-host update` and `velora update` update immediately. Pass `--no-update` or set
  `VELORA_NO_UPDATE=1` to turn background updates off. Builds made from source never update
  themselves.

<details>
<summary><b>How updates are checked</b></summary>
<br>

Each release carries `manifest.json`, which lists every file with its SHA-256. Updates come
over HTTPS from this repository's releases only, which are trusted as published (there is no
separate signing key). Before installing anything, an update checks:

- that the version is newer than the installed one (no downgrades);
- that every path stays inside the install directory;
- each file's hash and size.

Only files that changed are downloaded, so the FFmpeg libraries aren't fetched again unless
they changed. Files are swapped in by renaming. If any step fails, the update is rolled back,
and the previous files are removed on the next start.

</details>

## Usage

### Desktop

On a desktop, open **Velora** (`velora` with no arguments) on the computer to control, go to
**This PC**, turn sharing on and choose **Show QR code**; on the other computer, paste the code
or the `velora://` link under **New pairing**. With **Also let it access this PC** on (and
sharing on here), the other computer pairs back by itself, so each can reach the other.
Paired computers are listed under **Devices** as cards, one click away; each session opens in
its own window.

**This PC** also shows which devices are paired and connected, removes them, and sets the
access password. **Settings → Start with Windows** opens the app and/or turns sharing on at
sign-in.

On Windows, Velora also has an icon next to the clock. It shows whether this PC is shared and
who is connected, opens the app, and its menu turns sharing on and off or quits. Closing the
window leaves Velora there (**Settings → Keep running next to the clock when closed**), where
it announces devices asking to send files. Started at sign-in, it opens straight to the icon.

While sharing is on, the host keeps the computer from going to sleep, so it stays reachable
even when it sits locked for hours (**This PC → Keep this PC awake**, on by default). The
screen may still turn off, but stays on during a session. On Windows, `powercfg /requests`
lists both under Velora. A closed laptop lid still puts it to sleep.

Client shortcuts: <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>F</kbd> toggles
fullscreen, <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>Q</kbd> quits.

When a Windows host has several displays, a session starts on the main one and its window
title says which is shown ("Display 2 of 3").
<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>M</kbd> moves to the next display and
<kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>1</kbd>…<kbd>9</kbd> picks one; the mouse
follows. A Linux host streams its whole desktop, every monitor at once.

When a second paired device connects, it takes over the session. Switching from the phone to
the laptop just works.

### Command line

On the computer to control:

```sh
velora-host run --pair
```

This prints a single-use pairing code, valid for 10 minutes, a QR code for the phone, and the
exact command to run on the other device:

```sh
velora pair 192.168.0.10:7420 VL1-...      # first time: pairs, saves the host and connects
velora connect <host-name>                 # afterwards
velora list                                # paired hosts
velora bench <host-name> --seconds 10      # headless throughput/latency check
```

Host management:

```sh
velora-host clients                 # paired devices
velora-host revoke <name|fingerprint>
velora-host password [--clear]      # password paired devices must also type to connect
velora-host run --fps 60 --bitrate 12000 --bind 0.0.0.0:7420 --encoder auto
```

### Sound

On Windows, what the host plays comes out of the client during a session. It travels as Opus
at 96 kbit/s, 20 ms per datagram, through a short buffer: a lost packet is a 20 ms gap, never
a delay for the ones after it. <kbd>Ctrl</kbd>+<kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>A</kbd>
mutes it. Sound needs builds with FFmpeg (the released ones) on both computers; Linux hosts
and the Android app don't send or play it yet.

### Lock screen access (Windows)

**This PC → Access on the lock screen** (or `velora-host service install` as administrator)
installs Velora as a Windows service. It copies the app to `C:\Program Files\Velora`, keeps
the host's state in `C:\ProgramData\Velora` (readable only by SYSTEM and administrators,
paired devices and password are carried over), and starts the host as SYSTEM in the console
session. The host then follows the lock screen, UAC prompts and the logon screen, and runs
from boot. Installing also adds a Windows Firewall rule, "Velora (service)", that lets the host
receive UDP on port 7420 on any network, Public ones included: a service never gets Windows'
"allow access" prompt. `velora-host service uninstall` removes the service and the rule. Under
the service, only administrators can pair or remove devices and change the password.

### Shared clipboard

During a session, text and images copied on one computer can be pasted on the other, both
ways. Images travel as PNG (up to 32 MB). Turn it off under **Settings → Share the
clipboard**. Both computers need this version; with an older one, the clipboard stays apart.

### Files between computers

Both computers need this version or later.

- **In a session**, drop files or folders on the window: they go to the remote computer's
  Downloads folder. On the remote computer, **Send to → Velora** in Explorer sends the
  selection back to your Downloads folder. The window title shows the progress.
- **Devices**: drop files from Explorer on a computer's card to send them to its Downloads.
- **Devices → Files** opens a file manager with a computer on each side, this one or any paired
  one (pick it with the name at the top of the side). Select and use **Send to**, drag rows
  from one side to the other, or drop files from Explorer on the side that receives. Between
  two remote computers, files pass through this one (a temporary folder, removed afterwards).
  It connects for files only, without video, so it also works while a session is open, and
  leaves that session alone.

The computer receiving files asks first: "*X is asking to send files to this PC*", with the size
and where they go, **Accept** or **Decline**, and **Always accept from X** to skip the question
for that device from then on. Unanswered requests are declined after two minutes.

Nothing is ever overwritten: a name that is taken gets a number (`photo (1).jpg`). Files are
written under a temporary name and appear only once complete; a cancelled or interrupted
transfer leaves nothing behind. Symbolic links are not followed.

Any paired device can browse and move files, as the user signed in on that computer: it could
already do so through the screen. Under the lock screen service, file access runs in a helper
process started as the signed-in user, never as SYSTEM, and is unavailable while nobody is
signed in.

### Android

1. On the computer, run `velora-host run --pair`. It prints a QR code.
2. In the app, tap **Scan QR code**. You can also type the address and code.
3. Next time, tap the computer in the list. Long-press it to forget it.

The screen works like a laptop trackpad, and the cursor is drawn on the phone, so it follows
your finger with no network delay:

| Gesture | Action |
|---|---|
| Drag one finger | Move the cursor |
| Tap | Left click |
| Tap, then touch again and drag | Hold the left button (drag and drop, select text) |
| Two-finger tap | Right click |
| Two-finger drag | Scroll |

The toolbar shows or hides the keyboard and has Esc, Tab, the arrows and Del. Ctrl, Alt, Win
and Shift latch: tap Ctrl, then `c`, to send Ctrl+C. Text from the soft keyboard is typed in
whatever layout the host uses, including accents through dead keys on Linux (`á`, `ã`, `ç`).
USB and Bluetooth keyboards send physical keys. The video is decoded in hardware by
MediaCodec, straight to the screen.

When a newer release is out, the app offers to update when it starts: tap **Update** and
confirm. Paired computers are kept. Debug builds, such as the `velora-debug-apk` artifact of the
**Android** workflow, are signed with another key: they never update, and switching between
them and a release means reinstalling (and pairing again).

### Access over the internet

With a mesh VPN such as **Tailscale** or **Netbird** on both computers, nothing else is
needed. The host finds its addresses on the mesh (100.64.0.0/10, and Tailscale's
fd7a:115c:a1e0::/48), shows them under **This PC**, puts them in the pairing link, and tells
every client that connects. The client keeps them with the computer and, on the next
connection, tries them along with the usual address (that one first, each other one 250 ms
later): at home the LAN answers, away the VPN does, with no address to change. Only the
secure handshake races; the session opens on the address that answered first.

Without a mesh VPN, forward **UDP** port 7420 on the host's router. Every connection is
authenticated and encrypted either way. Built-in NAT traversal is not implemented.

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
full-screen scrolling text at 1080p (worst case for the encoder): about 40 fps and 25-30 ms
from capture to decoded frame with CPU encoders. GPU encoders haven't been benchmarked by the
project yet (no GPU in CI).

### Project layout

| Crate | Purpose |
|---|---|
| `crates/protocol` | Wire format, TLS/QUIC configuration with certificate pinning, pairing codes, identity storage |
| `crates/host` (`velora-host`) | Capture, color conversion and encoding, input injection, sessions |
| `crates/client-core` | UI-independent client: connection, input API, decoding. Mobile apps will reuse it through FFI |
| `crates/client` (`velora`) | Desktop client: launcher (egui) for pairing, devices and settings; session window (winit + softbuffer) |
| `crates/mobile` (`velora-mobile`) | Client core exported to the mobile apps through [UniFFI](https://mozilla.github.io/uniffi-rs/) |
| `crates/uniffi-bindgen` | Generates the Kotlin (later Swift) bindings for `velora-mobile` |
| `android/` | Android app (Kotlin): MediaCodec hardware decoding, trackpad, soft and physical keyboards |
| `crates/audio` (`velora-audio`) | The host's sound: WASAPI loopback capture and playback, Opus through FFmpeg |
| `crates/update` | Self-updates from GitHub Releases |
| `crates/release` (`velora-release`) | Release tooling used by CI: packaging and the update manifest |

## Building

Requirements: Rust 1.95+ and a C/C++ compiler (OpenH264 is built from source by the
`openh264` crate).

```sh
cargo build --release
# binaries: target/release/velora-host, target/release/velora
```

### Hardware encoding (recommended)

The default build encodes and decodes in software (OpenH264). For the GPU, build with the
`ffmpeg` features, which link the FFmpeg libraries (libavcodec, libavutil) dynamically:

```sh
# Linux (Debian/Ubuntu): FFmpeg development packages and clang (for bindgen)
sudo apt install libavcodec-dev libavutil-dev pkg-config clang
cargo build --release --features velora-host/ffmpeg,velora/ffmpeg

# Windows: an LGPL *shared* FFmpeg build (e.g. BtbN's win64-lgpl-shared) and LLVM
set FFMPEG_DIR=C:\path\to\ffmpeg     # contains include\ and lib\
cargo build --release --features velora-host/ffmpeg,velora/ffmpeg
# then copy the avcodec-*.dll, avutil-*.dll and swresample-*.dll from FFMPEG_DIR\bin next to the .exe files
```

`velora-host run --encoder auto` (the default) picks the first encoder that opens:
NVENC, then AMF, then Quick Sync on Windows, and NVENC, then VA-API, then Quick Sync on Linux.
If none opens, it falls back to software. To force one, pass `--encoder nvenc|amf|qsv|vaapi|software`,
or `--encoder ffmpeg:<name>` for any FFmpeg encoder. All hardware encoders are configured for
low latency: no B-frames, CBR, no lookahead, and keyframes only on demand.

On Windows, NVENC, AMF and Quick Sync take frames without them leaving the GPU: the D3D11
video processor converts the captured desktop to NV12 on the GPU that captured it, straight
into the encoder's own textures, and the CPU does none of it (measured with Quick Sync on an
Intel UHD 750: about 5 ms per 1080p frame). If that path fails, the host goes back to
converting on the CPU; `VELORA_ZERO_COPY=0` keeps it there.

The bitrate adapts to the network: `--bitrate` (12000 kbit/s by default) is the most. When
frames take well longer than usual to be acknowledged, or the host has to hold frames back,
it drops to 70% (down to a tenth of the most); once the path keeps up, it climbs back step by
step. The change applies in place, with no keyframe. `--fixed-bitrate` turns this off.

On the viewing side, `velora` draws on the GPU (OpenGL 3.3 / ES 3.0, software fallback). A
build with `ffmpeg` also decodes on the GPU: on Windows, D3D11VA decodes and the D3D11 video
processor converts the picture, which the window shows in place through `WGL_NV_DX_interop2`
(measured at 1080p: 2.7 ms per frame against 6–8 ms for OpenH264, and less CPU). Without the
interop, and with VA-API on Linux, the picture is copied back to memory, which is slower than
OpenH264 up to 1080p: then the GPU takes over only when the CPU falls behind (more than 12 ms
per frame, say at 4K). `VELORA_DECODER=gpu` or `software` forces one.

On Linux, VA-API needs the driver for your GPU (`intel-media-driver` or `mesa-va-drivers`)
and access to `/dev/dri/renderD128` (the `render` group).

### Linux runtime requirements

> [!IMPORTANT]
> The host needs an **X11** session: Wayland is not supported yet.

- Host: write access to `/dev/uinput` for input injection. Without it the host runs
  view-only. Example udev rule:

  ```sh
  echo 'KERNEL=="uinput", GROUP="input", MODE="0660", OPTIONS+="static_node=uinput"' \
    | sudo tee /etc/udev/rules.d/60-velora-uinput.rules
  sudo usermod -aG input "$USER"   # then log out and back in
  ```

- Client: `libxkbcommon-x11` (X11) or a Wayland compositor.

### Android app

Building the app yourself needs the Android SDK and NDK, Rust with the
`aarch64-linux-android` and `x86_64-linux-android` targets, and
`cargo install cargo-ndk`. Then run `cd android && ./gradlew assembleDebug`. Gradle compiles
the Rust core and generates its Kotlin bindings.

## Security model

- Each device has a long-lived self-signed certificate. There is no CA and no account server.
- The pairing code contains the host's certificate fingerprint and 128 random bits. The client
  pins the fingerprint, so even the first connection can't be intercepted, and proves it knows
  the secret over the encrypted channel. The host then stores the client's fingerprint. Codes
  are single use and expire.
- Every later connection is mutual TLS 1.3. The client checks the pinned host certificate and
  the host checks the client against its paired list.
- Keys and lists are stored in the OS config directory (`~/.config/velora` on Linux,
  `%APPDATA%\velora\config` on Windows), readable only by the user on Unix.
- Optional access password: paired devices must also send it (inside TLS) to open a session.
  Only a salted PBKDF2-SHA256 hash is stored; repeated wrong guesses lock that device out for
  a growing time.
- The launcher talks to the local host over a named pipe (Windows) or a Unix socket, open
  only to the user it serves, SYSTEM and administrators.
- File transfers use the same connection. The receiver checks every path it is sent: nothing
  can be written outside the chosen folder (no `..`, absolute paths, drive letters, alternate
  data streams or device names).

> [!WARNING]
> On Windows, without the service, input can't reach elevated windows unless `velora-host`
> runs elevated, nor the secure desktop (UAC prompts, lock screen).

## Roadmap

1. **Zero-copy capture on Linux.** On Windows, captured frames reach the encoder without
   leaving the GPU; on Linux they are still converted on the CPU and uploaded. Next: VA-API VPP.
2. **Zero-copy decoding on Linux.** Windows decodes and shows pictures without leaving the
   GPU; VA-API still copies them back. Next: import the VA-API surface into EGL (dma-buf).
3. **Mobile:** an iOS app (Swift + VideoToolbox) on the same `velora-mobile` core. On Android:
   pinch to zoom, a direct-touch mode, and Play Store publishing.
4. **NAT traversal.** A self-hostable rendezvous server, UDP hole punching, and a relay fallback.
5. Wayland capture (xdg-desktop-portal + PipeWire), display selection on Linux, cursor shape sync,
   sound on Linux and Android, relative mouse mode for games.
6. A systemd user service; installers.

## Releasing (maintainers)

<details>
<summary><b>How a release is published</b></summary>
<br>

To publish a release, bump `version` in the workspace `Cargo.toml` and merge to `main`. When
`main` has a version without a matching `v<version>` tag, the Release workflow (pushing that
tag by hand does the same):

1. builds Windows and Linux with FFmpeg (Linux on Ubuntu 22.04, for a low glibc requirement);
2. smoke-tests the packaged binaries;
3. builds the Android APK, signed with the release key, and checks the key;
4. writes the update manifest;
5. publishes the GitHub release and creates the tag.

The Android release key lives in the `ANDROID_KEYSTORE_BASE64` (a base64 PKCS#12 keystore,
alias `velora`) and `ANDROID_KEYSTORE_PASSWORD` secrets of the `release` environment, which only
`main` and `v*` tags may use, so pull request builds never get it. Keep a copy of it: installed
apps only accept updates signed with the same key, whose certificate fingerprint is pinned in
the Release workflow.

Merges that keep the version publish nothing. Pull requests that touch the release machinery
run the same build as a dry run.

</details>

> [!CAUTION]
> Every installed copy picks a release up automatically, so treat push access to this
> repository (and its tags) as access to every installation.

## License

MIT, see [LICENSE](LICENSE).

The desktop launcher bundles Inter and JetBrains Mono (SIL Open Font License) and Lucide icons
(ISC); their licenses are next to them in `crates/client/assets`. The tour video's music is
“Happy Beats / Business Moves” by ende.app, under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

> [!NOTE]
> H.264 is covered by patents. Cisco pays the royalties for OpenH264 only when users download
> Cisco's prebuilt binary. This project compiles OpenH264 from source, which isn't covered.
> Check your situation before distributing binaries. AV1, which is royalty-free, is on the
> roadmap. FFmpeg is used under the LGPL: link it dynamically and use an LGPL build.
