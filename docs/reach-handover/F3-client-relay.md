# F3 client relay dialer: hand-over for I3, G2 (and F4, E4, the review)

Branch `reach-f3-relay-dialer` (from `integration-wave2`, 0fc65e2). One file: `crates/client-core/src/reach/relay.rs`, which F1 left as two stubs;
the frozen signatures `dial_relay` and `wake_through_relay` are unchanged. 21 new tests in that file (68 in the crate); fmt, clippy `-D warnings`
and `cargo test -p velora-client-core` green on Windows, `cargo check -p velora-mobile` compiles. The tests run six times in a row in parallel and once
on one thread with no flake. I broke the code on purpose 15 ways (the hello bits, `relays_for_others` ignored, `RelayTo` to the wrong host, `Wake`
sent as `RelayTo`, no watch task, either connection not closing the other, a send that fails, a wake that says `Sent` for anything, an untyped refusal,
the host as its own relay, repeated relays, the version unchecked, no source address on received packets); each made a test fail except one (below).
Linux and Android were not compiled here.

## What a dial does (`reach::dial_relay`, called by the race)

1. **Outer connection** (`Link::open`): QUIC to the relay with `tls::client_config(identity, relay_fingerprint)`, then the Velora hello as a *link*
   (`files_only` and `reach`, nothing else: E1's rule, so that the relay starts no session and sends nobody away), no password, name = this device's.
   It reads the welcome (version checked), then waits for the relay's `Reach` and refuses to go on when it says `relays_for_others: false`, as T0
   requires; no `Reach` within 3 s means "too old to relay".
2. `RelayTo { fingerprint: host }` and the `RelayStatus` (`Link::ask`). A status that is not ok is a typed `Refusal(reason)`, with the relay's words.
3. **Inner connection**: an endpoint on a `RelaySocket` (quinn's `new_with_abstract_socket`), host certificate pinned, dialed at a made-up peer address
   (`fd00:7e1a::1`, local `::2`). The caller then sends the ordinary hello on it; `(Endpoint, Connection)` is what a direct dial returns.
4. A task (`watch`) keeps the outer connection and ends the pair: the relay ends the link -> the inner connection is closed at once (not after the 15 s
   idle timeout); the inner connection ends -> the outer one is closed after the inner endpoint has had up to 1 s to send its last packets, which frees the
   host for the next client. A dial that fails or is dropped closes the outer connection, so the relay is not left holding the host.

`RelaySocket`: the inner packets go out through D1's `Splitter` with `max_datagram_size()` read at every send; a task reads the outer datagrams through a
`Reassembler` (swept once a second) into a queue of 512; `may_fragment() == false`. **It never returns an error.** quinn 0.11 ends the driver of a
connection whose `try_send` fails without a word (it logs "I/O error" at error level and leaves the connection half alive, closed for nobody), so a
closed outer connection, a packet too big for two datagrams and a full queue are counted losses (the first and every 1024th are logged at debug), and
`poll_recv` stays pending when the outer connection is gone. `watch` is what reacts to that.

## For F4 (signaling through a relay) and E4

- `Link` and `Waits` are `pub(crate)`: `Link::open(identity, device_name, RelayRef, &Waits::DEFAULT)` gives a connection past the welcome to a relay that
  relays, `link.ask(ClientMsg::PunchRequest { .. }, &Waits::DEFAULT)` sends a request and returns `Err` carrying a `Refusal` (find it with
  `downcast_ref`) when the status is not ok. Keep the `Link` while you need the connection: dropping it closes it. Do not send `RelayTo` on it unless you
  mean to be relayed (one client per host and device: a second `RelayTo` from this device takes the first over).
- The test rig in `relay.rs` (`Rig`: a relay run the way E1's `serve_link` does, with D2's `Relay` and a fake magic packet; `TestHost`: a host registered
  with it, serving inner connections through a `RelaySocket`) is `cfg(test)` and private to the file; copy what you need for a punch test through a relay.
- E4: what the relay must do for this dialer is what `rig.serve_link` does: Welcome (any size), `Reach` right after it, `RelayStatus` for each
  request on the same stream, and not close the connection when the control stream ends (D2 keeps its handle). The dialer keeps the control stream open for
  the whole session.

## Decisions to review

1. **A relay PC with an access password cannot be used.** Links go through the host's `authorize`, which asks every device for the password. The
   dialer sends none: the only password it holds is the *host's* (`params.password`), which belongs to another computer, and a wrong guess at the relay
   counts toward that device's lockout there. A `PasswordRequired` from a relay is a failed dial (not the `PasswordRequired` error, which makes
   the applications ask the user for the host's password). E1/E4 could skip the check for links of paired devices; otherwise H1 should say it.
2. **Waits** (`Waits::DEFAULT`): 8 s to connect, 5 s for the welcome, 3 s for `Reach`, 5 s for each answer, 10 s for the inner handshake. The race has no
   timeout of its own for a dial, so these are the dial's. A relay address that does not answer therefore costs the race 8 s of that one candidate.
3. **The inner connection's close is local.** When the relay ends the link, `Session::closed()` says "closed" (quinn's text for a local close), and the reason
   ("another device took the host over", "the host left the relay", ...) is in the log at info level. A reason in the session's message would need F1's `lib.rs`.
4. **Wake** asks every relay address of the host's `relays` and `Relay` entries (at most 8, 250 ms apart, at the same time) and the first `ok` wins; every
   other outcome is `NoRelay`, and only a stored host fingerprint that does not parse is an `Err`. The link is named "velora" (the signature has no device
   name). `Unsupported` is F1's, not produced here.
5. **Datagrams are required**: a relay whose connection carries none fails the dial at once (D2 would refuse it with `NoDatagrams` anyway).

## Gotchas

- **One client per host and device** (D2). A files window (`connect_files`) and a session through the same relay, or two `velora` processes, take each other
  over, and the one taken over ends with the reason above. G2 should not offer both at once through a relay; F1's race already spaces the addresses of one
  relay 2 s apart for the same reason.
- **Rate limit** (D2): a burst of 6 new flows per device, one more every 5 s, shared by `RelayRegister`, `RelayTo`, `Wake` and `PunchRequest`. Each dial and
  each wake attempt costs one. A UI that wakes a host and then connects when it comes up should try no faster than one `RelayTo` per 5 s; `Refusal` carries the
  relay's "try again in N s".
- **Video packet size (I3, E4).** The host's endpoint discovers the path MTU up to 1452 bytes and sends video packets of that size to a relayed client, but an
  outer datagram carries about 1400, so every full-size packet becomes two datagrams (D1 handles it; the cost is about 1.6 times the datagrams per
  megabyte and a lost half losing the packet). E4 can accept relayed connections with a server config whose `MtuDiscoveryConfig` upper bound is about 1350. The
  client's own packets are small and its discovery does not matter.
- `Link` ignores whatever the relay sends after its answers; a relay that wants to tell a client something later has no channel here yet.
- The mutation that no test sees: the explicit `link.conn.close(..)` on a failed dial is redundant in the tests (the relay frees the host as soon as the inner
  endpoint has dropped its handles, a few hundred ms); it makes the release immediate when the inner handshake fails for a reason that keeps the endpoint draining.

## Not tested

Linux and Android compile; a real relay (E4: the tests run D2's `Relay` behind a copy of E1's link protocol); a relay on another network, a lossy outer path
(D2's tests lose 1% of the datagrams, these do not), IPv6 relays, an outer connection that migrates; the whole thing under video load.
