# F5 mobile surface: hand-over for H1 and the Android work (and I2)

Branch `reach-f5-mobile` (from `integration-wave3`, d60b4fa). One file: `crates/mobile/src/lib.rs`. Nothing that existed is renamed, removed or changed in
signature, and no dependency is added. 5 new tests in that file; fmt, clippy `-D warnings`, `cargo test -p velora-mobile` and `cargo check -p velora-mobile`
green on Windows. I broke the code on purpose 16 ways (each kind of address named as another, the kinds repeated, reversed or cut to the first, each wake
outcome mapped to another, `hosts()` without the kinds or with name and address swapped, `wake` asked for the wrong computer or made never to fail); each made
a test fail. I also built the library and ran `uniffi-bindgen` on it here, so the Kotlin below is what the generator wrote. **Not run:** the Android CI job
(cargo-ndk, Gradle, `assembleDebug`; this PC has no Android Rust target or NDK) and anything on a phone.

## What the Kotlin side gets

```kotlin
data class HostEntry(var name: String, var address: String, var kinds: List<AddressKind> = listOf())
enum class AddressKind { LAN, VPN, PUBLIC, V6, RELAY, OTHER }
enum class WakeOutcome { SENT, UNSUPPORTED, NO_RELAY }
// on Client:
@Throws(MobileException::class) fun wake(host: String): WakeOutcome    // blocking
```

`kinds` has a default (`#[uniffi(default = [])]`), so `HostEntry(name, address)` still compiles. Nothing under `android/` builds a `HostEntry` or implements
`ClientInterface` (the app uses the concrete `Client`), so the sources and unit tests there should compile as they are; I read them, I did not build them.

## `HostEntry.kinds`

- The distinct kinds of address the computer listed in its last `Reach` (`KnownHost.kinds`, saved by F1), in the order it listed them, each once. `Relay` and
  `Other` lose their payload (the relay's fingerprint, the unknown code): the app has no use for them.
- **Empty means "has not said"**: paired before this version, an older Velora on the computer, or not connected since. It does not mean the computer has no
  address, so do not show it as "home network only".
- It is what the computer listed, not what works from where the phone is. For a hint on the device list: `PUBLIC`, `V6` and `RELAY` can be used from other
  networks, `VPN` only when the phone is on the same mesh, `LAN` at home. The race in client-core decides what really connects.

## `Client.wake(host)`

`host` is a `name` from `hosts()` or the main address, as for `connect`. It calls `hosts::wake` (F1):

1. The computer never reported its adapter's address: `UNSUPPORTED` (connect to it once while it is awake).
2. One of the phone's own IPv4 networks holds a LAN address of the computer: the packet goes out there (directed and limited broadcast, ports 9 and 7):
   `SENT`.
3. Otherwise it asks the relays the computer is registered with (F3): `SENT` when one sent the packet, `NO_RELAY` when none could (the phone is not on the
   computer's network and no relay answered).

It throws `MobileException.Failed` for a computer that is not paired (`'x' is not paired yet`) or when the device's own identity cannot be read; never
`PasswordRequired`, and `UNSUPPORTED` and `NO_RELAY` are outcomes, not exceptions. It **blocks**: at once for the home network, and up to about 25 s when
relays are asked and do not answer (per relay: connect 8 s, welcome 5 s, `Reach` 3 s, answer 5 s; up to 8 relays at once, 250 ms apart), so call it from
`Dispatchers.IO`. It does not wait for the computer to wake: `SENT` says the packet left, nothing more.

```kotlin
val outcome = withContext(Dispatchers.IO) { try { client.wake(entry.name) } catch (e: MobileException) { null } }
when (outcome) {
    WakeOutcome.SENT -> { /* connect in a few seconds, and again if it is not up yet */ }
    WakeOutcome.UNSUPPORTED -> { /* "connect to it once while it is awake" */ }
    WakeOutcome.NO_RELAY -> { /* "not on its network, and no other computer there could send it" */ }
    null -> { /* not paired any more */ }
}
```

Waiting for the wake: a PC needs from several seconds to a minute or more to answer. Try `connect` no faster than once every 5 s: through a relay the allowance is 6
new flows per device at once and one more every 5 s, shared by register, relay-to, wake and punch (D2), and a faster loop ends in refusals from the relay
(`RateLimited`).

## What H1 can say

Waking from the phone needs: the computer set for Wake-on-LAN in its firmware and adapter (nothing here can see that); the computer connected once with this
version, so that the phone knows its adapter's address; and the phone either on the computer's Wi-Fi or LAN, or another paired computer on that LAN with
"relay for others" on. The app needs no new Android permission: `INTERNET` is enough to send the broadcast.

## A risk for "wake works from the phone on the home Wi-Fi" (not in my file)

Step 2 above lists the phone's networks with `velora_nat::wake::wake_networks()`, which is built from `local_macs()`, and `macs_of` there drops every adapter that
has no usable MAC of its own. On Android `netdev` 0.31 reads the MAC from the link-layer records of `getifaddrs`, and apps no longer get those on recent Android
(the MAC address restrictions of Android 10 and 11). So I expect `wake_networks()` to be empty on a recent phone: the home-network leg is skipped, the call falls
through to the relays and answers `NO_RELAY` although the phone is on the computer's LAN. The phone's own MAC is not needed to send a magic packet (the packet
holds the target's MAC; `wake_on` only binds to the network's local address), so the filter comes from reusing `local_macs`, not from a need. **This is from
reading `addresses.rs`, `wake.rs` and netdev's `unix.rs`; nothing here ran on Android.**

Fix to put in a ticket (B2/B3, `crates/nat`): make `wake_networks()` list the IPv4 networks of adapters that are up, not loopback and have a real address, with or
without a MAC (keep `local_macs()` as it is, the host needs it), with a unit test on an adapter whose `mac` is `None`. An alternative in F1's `wake_on_lan`: when
`wake_networks()` is empty, send to `255.255.255.255` (ports 9 and 7) and to the /24 broadcast of each LAN address of the computer. Either way, check on a phone;
the ticket's "done when" is the part nobody could verify here. A second thing to look at there: on a Wi-Fi without internet Android may keep the app's sockets on
mobile data, and then the broadcast may not leave through the Wi-Fi (`ConnectivityManager.bindProcessToNetwork` around the call, on the Kotlin side, if so).

## Decisions to review

1. **`WakeOutcome` is its own enum with the client's three names**, not a Boolean or a string: the app decides its words. The conversion is an exhaustive `match`, so
   a variant added to client-core breaks this crate's build until someone gives it a Kotlin meaning. `AddressKind` follows the same rule.
2. **`kinds` is a plain list with a default, not an `Option`**: `isEmpty()` is the whole test in Kotlin. The meaning of empty is in the doc comment, which the
   generator copies into the KDoc.
3. **Only the kinds, not the addresses.** The ticket says kinds; the IPs would put numbers on a screen nobody reads. A details screen can get a second field later,
   additively.
4. **`wake` blocks with `block_on`, like `pair` and `connect`**, not a UniFFI async function: the crate exports none and the app already runs these on `Dispatchers.IO`.

## Not tested

The Android build and its unit tests; `wake` from a phone on the home Wi-Fi, from a phone on mobile data through a relay, and the risk above; the Kotlin calls (I
did not write app code); Linux and Android compile of this crate.
