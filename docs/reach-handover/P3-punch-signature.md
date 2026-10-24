# P3 punch signature and the keepalive's answer: hand-over for I4, E2, E3 (and G2, the review)

Branch `reach-p3-punch-signature` (from `integration-wave3`, 410e8d8), code in efaffc4, a comment-only commit in c286622. One file
of code, `crates/host/src/reach/punch.rs` (E5's), and this note. 15 new tests (the module has 66, the host crate 344 and 5
`#[ignore]`d); `cargo fmt --all --check`, `cargo clippy -p velora-host --all-targets -D warnings` and `cargo test -p velora-host`
are green on Windows. The module's tests ran 30 times in a row, 5 times on one thread and 5 rounds of two copies at once, and the
whole host suite 5 times, with no failure. Linux was not compiled here. I broke the code on purpose 63 times (E5b's mutants
adapted, and new ones for the signature, the resume rule, the reply check and its comparison, the gap and its growth, what was
not confirmed, which nodes are asked, the silent round, the wall clock and the simulator's restart): each made a test fail. A
fresh agent read the change cold, as for E5b; what it found and what changed is in the last section. No packet left the loopback.

## 1. The signature without `Public`

E2 found (its note, "Findings outside E2's file") that `network_signature` listed the `Public` addresses next to `mapping.external`:
they only repeat the mapping's address, E2 adds and takes them away as its verdict about the mapping changes (a verdict it makes
from `observed`, this task's output), and every such change made this task measure again and, when the round learnt nothing, drop
`observed`. The signature is now **the LAN addresses, the IPv6 addresses and `mapping.external`**. Tested, on the pure signature and
on the running task: a change of E2's verdict (`Public` coming and going, the flags or the lease of the mapping) makes the host
neither measure again nor drop what it measured; another address of the router, or no mapping, still does.

There was a second path to the same loop, and it was mine: E5b's `keepalive_wanted` included "no `Public` address advertised", and
the host measured at once when the keepalive became wanted after a time when it was not (`Pause::Resumed`), so E2 withdrawing the
mapped address made the host measure. **Only `keepalive_allowed` (standalone on, the DHT switch on, no relay registered) triggers
that measurement now**; whether the record advertises the endpoint (`advertises_punch_endpoint`: cone NAT, `observed` set, no
`Public` address) only decides whether the keepalive is sent. When E2 withdraws its address the keepalive begins at once, and its
answer (below) says whether the endpoint moved.

## 2. A keepalive's answer is compared with `observed`

The answer to the keepalive says where the DHT node sees the socket (BEP 42). `Keeper::keep` returns what it learnt (`Seen`):
`Same`, `Changed(endpoint)` or `Nothing` (nothing sent, no answer, no address in the answer, an address that is not on the
internet, or nothing measured to compare with). Only the whole endpoint counts, port included (a port that changed is the usual
remap), and only an address on the internet (a node inside a provider's network that says a private one, as S0 saw twice in 136
replies, changes nothing). When it is `Changed`, the NAT made another mapping (a router restarted, the computer woke up) and the
endpoint in the record leads nowhere: `pause` returns `Pause::Remapped` and `run` measures again at once, which updates `observed`
(and E3's record) if the nodes agree on the new endpoint. Four rules keep that from becoming a loop or a nuisance:

- **A gap, `REMEASURE_GAP` = 60 s**, counted from the end of the last measurement of any kind. A change seen sooner is not lost: the
  keepalive goes on, and the next one after the gap says it again. The gap counts the wall clock as well as the monotonic one, since
  the monotonic clock stops in a suspend on Linux and macOS and a computer that has just woken up is the case this is for.
- **The gap doubles** for each measurement a keepalive starts, up to the interval between periodic measurements (10 minutes), until
  a keepalive sees the endpoint as it was measured. A mapping that changes between every two keepalives (a carrier that keeps a
  UDP flow for less than 20 s and picks a port at random) is chased less and less, and in the end as often as before P3.
- **An endpoint a measurement did not confirm is not asked for again.** A node that always says another endpoint (one of two
  uplinks, a node that is wrong) costs one round; any measurement nobody asked for (the periodic one, a move) forgets it.
- **The keepalives go to the nodes that told the host where it is in the last measurement** (the votes that count). The nodes that
  answer without the address (B2: dht.transmissionbt.com does, router.bittorrent.com does not answer at all) say nothing about the
  mapping, and with all of the resolved addresses in the rotation only two keepalives in five could say anything. Before a
  measurement has any voters the keepalive goes to every node, as in E5b.

And a measurement that a changed keepalive started and that **learns nothing drops `observed` and `nat`**, as one after a change of
network does: the keepalive has just shown that endpoint to be dead, and E3 would go on publishing it until a round succeeded (30 s,
then 60, up to 5 minutes).

When it notices: at the next keepalive that goes to a node that says where the host is, so within 20 s of the remap, or within 80 s
when it happens just after a measurement (the gap), and later after a run of chases. Before, up to the next measurement (10 minutes)
or a change of the LAN or IPv6 addresses. What it costs: nothing in the normal case (the answer is read, not asked for); one
measurement round (a few datagrams) and one E3 publication for each change it finds, at most one a minute. It only runs while the
keepalive does, that is, not while a router mapping is advertised (E2 renews that one itself).

## The NAT simulator: `SimNat::restart()` (`punch::nat_sim`, test only)

The NAT forgets its mapping now, as a router does when it restarts: what arrives for the old port is dropped (even from a peer the old
mapping let in), the next packet that leaves goes out from another port, and the filter is empty. It shares `remap` with the expiring
NAT. The end-to-end test: a host behind a NAT with the keepalive running, the NAT restarts, the host's record leads to the new port
after one keepalive and one gap, and a client that dials it gets through.

## Decisions to review

1. **`mapping.external` stays in the signature.** The ticket says to keep "what really says the network changed" and to test that "a
   change of E2's mapping does not by itself trigger a new measurement". I read the second as E2's verdict (what the loop is made of),
   which is what E2's own finding asks (drop `Public`, keep Lan, V6 and `mapping.external`). The router's external address changing
   is news: this task learns the endpoint the nodes see, E2's note (residual (a)) wants that word fresh after the provider gives the
   PC another address, and the reply check does not run while a mapped address is advertised (no keepalive then). A change of
   `mapping.external` does not come from this task: E2 changes it when the router's answer changes, damped by its own backoff. If
   you want it out, delete the third element of `network_signature` and flip the last assertions of the two tests that name it.
2. **The resume measurement no longer follows E2's verdict.** E5b's note said the host measures at once when "a router mapping
   lapsed" (the `Public` address went and the keepalive began). It does not any more: the first keepalive's answer does the job with
   one datagram, and if the endpoint moved it measures.
3. **`REMEASURE_GAP` is 60 s and doubles.** Shorter finds a remap sooner after a measurement and lets a mapping that really changes
   often cost more rounds; the doubling bounds that. One constant, a field of `Timing` for the tests.
4. **A remap counts as a move** for the round that follows (`moved`): if that round learns nothing, the old endpoint is dropped. If
   the keepalive that asked for it was misled by a wrong node, a round that happens to learn nothing then drops a good endpoint until
   the next round succeeds (30 s at first); with the memory above the same node costs one round.
5. **The keepalives are concentrated on the nodes that vote.** With the default names that is two or three nodes instead of eight
   addresses, each getting a ping every 40 to 60 s from this host. They are public bootstrap nodes that answer far more than that.
6. **The comments of E5b's that ran past 120 columns** (48 lines, up to 130, my slip: the file had none before) are wrapped in a
   commit of their own, c286622, which changes comments and nothing else (checked by comparing the code lines before and after).
   Drop it if you would rather not have the churn.

## Still open (not done, not part of this ticket)

- **`Unknown` is not measured again sooner.** With two answering nodes, one of them private, or one informative node among those
  that answered, the NAT is `Unknown`: an endpoint, no listing, no keepalive, for 10 minutes (any answer is a good round). A retry
  at `retry_min` (doubling to `retry_max`) when the type is `Unknown` is a few lines in `run`; the cold review asks for it, since a
  remap is when one informative vote is likeliest. E5b's note, decision 7.
- **`Pause::Resumed` has no gap.** A relay registration that is lost and made again gives a measurement each time the last relay
  is gone; E4's retries (5 s, then longer, up to 5 minutes, starting over after a registration that lasted a minute) bound that,
  this task does not. Gating it with the gap needs a timer arm in `pause` so that the measurement is not lost.
- **`mapping.external` going from none to an address counts as a move** (E5's rule, unchanged): a silent round then drops `observed`
  although the host did not move.
- **`V6` is in the signature and E2 lists it in the OS's order off Windows** (B2, decision 1): an adapter whose first global address
  flips between E2's looks would make the host measure every minute, with the drop rule.
- E5b's decisions 4 (a relay on the LAN or over IPv6 does not hold the WAN mapping) and 5 (third parties see a ping every 20 s)
  stand.

## What the others must know

- **E2**: several of your comments say that a change of `Public` makes E5 measure again. It does not any more (the file is not mine
  to change): `mapping.rs` lines 35 and 263-264, the test comments at 1185 and 1451, and in `E2-host-mapping.md` the sentences about
  E5 measuring again at 21, 39, 46-47, the "E5" bullet (96-99), "until E5's signature stops including `Public`" (135-136) and the
  finding at 150-153. Your behaviour needs nothing: the damping stays. What changes for you is that a withdrawal of `Public` is
  followed by a keepalive and, if the endpoint moved, a measurement within about a minute, and not by a measurement at once; a
  recovery that changes no address (a VPN switched off) is seen at the next measurement, up to 10 minutes. The LAN addresses still
  change when a VPN does.
- **E3**: `observed` can change within about a minute of a remap, so the record is published again then (once a minute at most, and
  less often while a mapping keeps changing).
- **I4**: to try on a real network: restart the router, or sleep and wake the computer, with the DHT switch on and no mapping: the
  log says at info "a DHT node sees this computer at ... now: measuring again" within a keepalive and a gap, then "the NAT shows
  this computer as ..." with the new endpoint, and the record follows.
- **Superseded in E5b's note**: the host no longer measures at once when "a router mapping lapsed" (50-51, 1st bullet of section 2);
  "not done: noticing a changed mapping at once" (decision 8) is done here; "the record stays wrong until the next measurement, at
  most 10 minutes" (116-118) holds only for a remap no keepalive sees (a mapped address advertised, no DHT switch).

## What changed after the review

A fresh agent read the change cold (the brief named the files, E2's note and what to look for, not what I thought of it). It found no
defect in the signature change: this task is the only writer of `observed` and `nat`, E2 only reads them, E3 and E4 feed nothing
back, and `mapping.external` is the only trigger that catches a lost or re-granted router mapping while a `Public` address is
advertised, when the keepalive is off, so it stays (decision 1). It found, besides what is under "Still open", these, all fixed:

1. The reply check had no memory and no backoff. A node that always says another endpoint (one of two uplinks) made the host
   measure every time the rotation reached it, for ever, and a NAT that keeps a UDP flow for less than 20 s made it measure, and E3
   publish (about 600 datagrams), every minute or so, where before P3 it was every 10 minutes. The gap doubles now, and an endpoint
   a measurement did not confirm is not asked for again.
2. The rotation went through every resolved address, the ones that never put the address in the answer included (B2: only two of
   the four default names do), so only two keepalives in five could say anything; a change seen inside the gap was lost with them,
   and "its first answer says whether the endpoint moved" was mostly false. The keepalives go to the nodes that voted.
3. A measurement started by a changed keepalive that learnt nothing kept the endpoint the keepalive had just shown to be dead. It is
   dropped now, as after a move.
4. The gap used the monotonic clock alone, which stops in a suspend on Linux and macOS, so a computer that had just woken up could
   wait a minute of awake time. The wall clock counts too.
5. Tests: one decided `Same` or `Changed` in a 200 ms window (a late reply under load reads as none; 1 s now), and none had a node
   that answers without the address or a silent round after a remap (both added).

It also named the comments this change makes false in E2's and E5b's files and notes (listed above), and the items under "Still
open".

## Not tested

A real router restart or a real suspend and wake (the simulator's `restart` and the fake nodes stand for them); a carrier that moves
the host's port between two keepalives; the real DHT nodes (which answer without the address, which not at all); IPv6 (the DHT is
IPv4); Linux and Android compile.
