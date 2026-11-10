# Spam and DoS resistance for Pubky public listeners

Pubky identities are free: anyone can generate a key pair at no cost, so one attacker can appear as a million senders. Keys, follows and tags indexed by Nexus already form a trust graph for social use. The remaining problem is narrower: services that accept writes from keys they have never seen. Today these public listeners are pubky/inbox, which accepts pings, and homeserver signup.

## 1. Where each listener stands

| Listener | Who can write today | Current defences | Exposure |
|---|---|---|---|
| pubky/inbox | Any key. A session comes from a root-signed grant verified offline; the homeserver is never contacted (`docs/architecture.md`, "Session exchange"; `docs/authentication.md`) | Five layers: per IP (500 sign-ins/day, 2,000 pending pings, at most 50 pings per origin in one inbox, shrinking as others fill it), per identity, per recipient (1,000 pending), service-wide caps, request size (`docs/spam-and-abuse-resistance.md`) | Open first contact. The attacker's only cost is IP addresses. Botnets are out of scope by design, and about 240 addresses fill an offline recipient's inbox. Each junk ping also costs the recipient's client a fetch and a failed decrypt (`docs/pings.md`, "Keep your inbox from filling up") |
| Homeserver signup | `signup_mode = "token_required"` by default. Tokens are single-use, issued by an admin, and carry a quota (`pubky-homeserver/src/client_server/auth/signup_service.rs`, `src/data_directory/config.default.toml`) | Per-path rate limits by IP or user (`config.sample.toml`) | Already gated. pubky/homegate issues tokens for SMS, a Lightning payment (phoenixd), IP and Google verification (`README.md`) |

Homeserver signup tokens are close to the primitive that's needed: a single-use statement from an issuer that admits one key. They are bearer codes, though, consumed by whichever key presents them first. Homegate is already an issuer that accepts several kinds of proof. The answer applies the same pattern to the inbox, with every ticket bound to its sender key, and adds no new system.

## 2. Threat model

**Assets**

- First-contact availability: a customer or new acquaintance can still reach a user, and known contacts are never crowded out.
- Listener resources: storage, database connections and CPU.
- Recipient client work: each accepted junk ping costs a fetch, a decrypt and possibly a push.

**Attackers**

- **A. Scripted spammer.** A handful of IPs and unlimited keys. This is the inbox's current model, and its IP limits hold against it.
- **B. Rented-address spammer.** Hundreds to thousands of addresses from residential proxies, cloud servers and free IPv6 `/48`s. This defeats per-IP limits: about 240 addresses fill an inbox.
- **C. Botnet.** Tens of thousands of addresses, each with a CPU comparable to a phone, plus GPU time for rent.
- **D. Targeted harasser.** Low volume and persistent against one recipient, using fresh identities.
- **E. Griefer.** Turns the defences into weapons: false blocks, filling shared caps, making honest users pay.

**Out of scope:** volumetric network floods, which the CDN or hosting provider handles; compromised contacts, which the recipient's client blocks; content moderation.

**Goals**

1. The cost of opening a new edge (a first contact from one sender to one recipient) scales with the number of victims, not with listener capacity.
2. Admitted relationships pass free.
3. Under load, a listener first sheds the lane whose proof is cheapest to forge, and it never sheds known contacts.
4. There is no hard dependency on Bitcoin, on a single issuer or on Nexus.

**Principle: charge per new edge, never per message.** The inbox already keys pings by (sender, recipient, slot). Spam at scale means creating new (sender, recipient) pairs in quantity, so the defence sits only where a pair is first admitted.

### Pooling and replay

A bearer credential, valid for whoever holds it, can be pooled: an attacker collects, buys or steals many credentials and spends them from one botnet. Replay is the same attack in time: a credential that is spent once gets spent again, at another recipient or another deployment. Both turn per-user budgets into one attacker budget.

No ticket kind is a bearer instrument:

- Every ticket names the sender key as `sub` and is valid only on a request authenticated as that key. The inbox session is bound to the key that signed the grant (`docs/authentication.md`), so a copied ticket is useless without the sender's secret key.
- Invites and vouches also name the recipient, so they admit exactly one pair.
- Sponsor credentials are bound to the sender key and one inbox deployment, and they grant a small quota of new pairs that the inbox counts per key.

"Selling a ticket" therefore means selling the key itself. That is the residual risk below.

## 3. The primitive: an admission ticket

An admission ticket is a small signed statement that a sender presents with a first-contact write:

```text
ticket = {
  v:     1,
  kind:  "invite" | "vouch" | "sponsor" | "pow",
  sub:   <sender pubky>,           // required; valid only on a request authenticated as sub
  rcpt:  <recipient pubky> | null, // required for invite, vouch, pow; null for sponsor
  aud:   <inbox deployment audience>, // the exact string the inbox publishes
  n:     <new pairs per window>,   // invite and vouch: 1
  win:   <window seconds> | null,
  exp:   <unix seconds>,
  id:    <16 random bytes>,
  iss:   <issuer pubky> | null,    // null for pow
  proof: <Ed25519 signature by iss> | { epoch, nonce, effort }
}
```

**Inbox check, cheapest first** (the inbox's own design rule, "Reject cheaply and early"):

1. Check the size.
2. Check `exp` and `aud`, and that `sub` equals the session's identity. Check that `rcpt`, where set, equals the ping's recipient.
3. Check that `sub` isn't burned (see "Abuse reports and issuer standing" in §4), that the policy enables this kind, and that its lane has room.
4. Check that `iss` is in the trusted set, or that the PoW effort meets the current requirement.
5. Verify one signature or one PoW.
6. Charge it, in the bounded spend table, whose records expire with `exp` like inbox replay records:
   - **Invite:** spend `id` once.
   - **Vouch:** spend `(iss, sub, rcpt)` once, and charge the voucher's daily budget.
   - **Sponsor:** charge one unit of `sub`'s quota for the current window.

**On success,** the inbox records an admitted pair: a new, bounded table of (sender, recipient, how it was admitted, last used). Later pings in that pair, and replacements, need no ticket. A pair also counts as admitted when the recipient has pinged the sender before (a reverse edge). A refused first contact gets one code, `429 not_admitted` or similar, whatever the reason.

**Why replay fails:**

- A ticket presented again for the same pair finds the pair already admitted, so nothing is charged.
- An invite or vouch presented for any other recipient fails the `rcpt` check.
- A sponsor credential spends one quota unit per new recipient, so reusing it is simply spending its quota.
- At another deployment, the `aud` check fails.

**What the ticket deliberately leaves out:** scores, global reputation, per-message stamps and network lookups on the hot path. Every kind comes down to one of two checks: one signature against a key set named in the policy, or one PoW verification.

## 4. Proof kinds, and the options weighed

### Build now

**invite** (the issuer is the recipient). This is the signup-token pattern, issued by a user instead of an operator. The recipient's client signs the invite offline, naming one sender and itself, for single use. Whichever side already knows the other's key issues the invite:

- **In person,** one side scans the other's key from a QR code.
- **At a checkout,** the buyer's client reads the shop's key from the site and issues the shop an invite, and the shop's reply then opens the pair.

**vouch** (the issuer is someone the recipient already admits). A contact introduces one named sender to one named recipient. The inbox checks that it holds an admitted pair between `iss` and the recipient. That is trust-graph distance 2, proved with one signature and no graph query.

- A budget per voucher, for example 20 introductions a day, bounds a careless or compromised friend.
- Trust is relative to the recipient, which avoids the weakness the inbox docs record for global status: one follow from a reachable account makes any number of identities `networked` (`docs/spam-and-abuse-resistance.md`, "Rejected approaches").

**sponsor** (the issuer is a gate the operator trusts). A sponsor credential is bound to one sender key and one inbox deployment, and grants a small quota of new pairs: for example, "`sub` may open 5 new pairs a day for 90 days at this inbox". The inbox counts the quota per key. The credential can't be transferred, and every pair it opens uses up quota.

- Homegate already turns SMS, Lightning, IP and Google proofs into signup tokens. The same routes can issue sponsor credentials, and any payment rail (card, SEPA, Lightning, USDT) is just another route.
- A verified signup can mint the first credential for the new key automatically. This delivers "sponsor each new user" as a bounded budget, without buying PoW on users' behalf.
- Anyone can run a gate, and each inbox operator chooses which issuers to trust.

**Abuse reports and issuer standing.**

- **Who can report.** A recipient can report a sender only through a pair that sender opened with a ticket. Each recipient can make at most one report per pair. Reports therefore need a real first contact from the reported key, so an attacker can't create recipients for free and report innocent senders, the weakness the inbox docs give for rejecting server-side blocking.
- **Burning.** Once a key gathers reports from enough distinct recipients (an operator threshold, for example 3), its admission is burned: the inbox accepts no more sponsor, vouch or PoW tickets from it. Invites still work, because each one is a recipient's explicit choice. Pairs already admitted stay admitted.
- **Issuer standing.** Each report also counts against whoever admitted the pair: the gate that sponsored it, or the voucher who introduced it. Operators see reports per issuer as a share of the pairs it opened. They can lower an issuer's caps, or drop it from the policy. A voucher above the threshold loses its right to introduce at this inbox.
- **Where accountability lands:** on keys that paid or vouched, and on a few chosen issuers, not on free identities or shared IPs.

**Residual risk: Sybil keys at the gate's price.** An attacker who buys N credentials from a gate holds N keys, each opening a few pairs a day until reports burn it. The cost of one spam pair is roughly the gate price divided by the pairs a key opens before it is burned. With a quota of 5 a day and a burn after 3 reports, that is a few dozen pairs at most. The defence makes spam cost a known price per victim, set by the gate. It doesn't make spam impossible. If an issuer's price is too low for the abuse it lets through, operators raise its price, lower its quota or drop it.

**Why reverse edges and invites stay primary.** They cost honest users nothing. The recipient chooses them. Each admits exactly one pair, between two named keys, so pooling them is impossible: an invite issued to another key is worthless to an attacker, and the only way to get one is to be the key a recipient chose. Sponsors are the paid fallback, for reaching someone who hasn't invited you and whom no shared contact will vouch for.

### Build later

**pow.** A self-minted stamp bound to `(sub, rcpt, aud, epoch)`. Tor's onion-service PoW is the model (Equi-X; https://spec.torproject.org/hspow-spec/):

- It is off while the service is idle.
- Under load, the listener advertises a suggested effort.
- Effort decides a client's place in a priority queue. It isn't a wall.

PoW is the only permissionless lane: it needs no issuer, no graph and no payment. Its weakness is the reason BIP154 gave for withdrawing PoW: phones are the weakest hardware, facing botnets and rented GPUs, and work can be bought cheaply when demand is low. So PoW must never be a phone user's only way in. Honest mobile users hold invites, vouches or sponsor credentials, and PoW serves senders who have none of those. Binding the stamp to `rcpt` makes the cost grow with each victim.

Self-minting and buying work from a market pull the hash choice in opposite directions. An outsourcing market wants an ASIC-friendly hash such as SHA-256. Self-minting on phones wants a CPU-friendly one such as Equi-X. Buying admission is already covered by a sponsor credential bought from a gate: the economics are the same, verification is one signature, and no miner market is needed. The PoW lane is therefore tuned for self-minting.

### Not now

- **Proof of UTXO ownership** (taproot ring signatures). This is the strongest cost signal: capital stays locked, it can't be pre-mined, and ring signatures keep it private. It costs much more:
  - only Bitcoin holders can use it;
  - the verifier needs the UTXO set, from a full node or a trusted oracle;
  - each listener has to verify ring signatures and keep nullifiers so one UTXO doesn't admit everywhere;
  - it is an order of magnitude more complex.

  It fits later as a gate route: the gate verifies the UTXO proof and issues sponsor credentials, so listeners never touch Bitcoin.
- **Per-message payments** (Lightning or another rail). Paying per message adds friction and needs a payment rail for every sender. Prepaid credentials from gates cover the cost now. A per-edge payment stamp for merchant inboxes can come later as a sponsor variant whose issuer is the recipient itself.
- **Timestamps of identity age** (Bitcoin, OpenTimestamps, a Haber–Stornetta server). One Merkle root timestamps a million keys for the price of one, so age proves nothing about a single identity. A listener's own first-seen time, the inbox's parked "probation" idea, is cheaper and can't be faked in bulk without spending at that listener.
- **VDFs.** A VDF proves sequential time, not a cost per identity, and an attacker computes one for each identity in parallel. There is also no live peer-to-peer deployment to copy.
- **Global trust scores** (Nexus TrustRank in `nexusd/src/trust/engine.rs`; `SocialGraphStatus` `new` / `networked` / `established` in `nexus-common/src/models/user/social_graph.rs`). These are good display signals. As a gate, `networked` is one follow away. A later option is a Nexus instance acting as an issuer of short-lived `established` attestations, which a policy selects like any other issuer. Nexus doesn't sign attestations today (assumption, verify).

## 5. Policy layer

Policy is set at two levels:

- **The operator,** in the inbox configuration: which kinds are on, the trusted issuer keys and their caps, lane capacities, and PoW effort bounds.
- **The recipient,** in an inbox account setting: which kinds may reach them. For example, a person might allow "known pairs and vouches only", while a shop allows "invites, sponsors and PoW".

```toml
[admission]
first_contact = "ticket"                 # "open" keeps today's behaviour
kinds = ["invite", "vouch", "sponsor"]   # "pow" stays off until metrics call for it

[admission.vouch]
per_voucher_per_day = 20

[[admission.issuer]]
key = "<gate pubky>"
max_pairs_per_sub_per_day = 5
max_pairs_per_day = 100000

[admission.reports]
burn_after_distinct_recipients = 3

[admission.lanes]                        # shares of new-edge capacity
vouch = 0.4
sponsor = 0.4
pow = 0.2

[admission.pow]
mode = "under_load"
```

**Lanes.** Each kind gets its own share of a recipient's pending-ping capacity for new pairs and of the inbox's overall rate of new pairs. A flood in the permissionless lane therefore can't use up the issuer-backed lanes. Admitted pairs sit outside every lane.

**Shedding order under load:** PoW first, then sponsor (per-issuer caps before the shared ones), then vouch. Admitted pairs are never shed.

Lanes are keyed by the proof the sender presents, and the only relationship data they use is pings the inbox already sees. That answers the objection the inbox docs raise to "known vs unknown lanes", which needed recipients' contact lists.

**Clients show each first ping's lane,** for example "introduced by @x", "sponsored by \<gate\>" or "proof of work". Users and apps can sort by it, and a junk introduction can be traced to whoever vouched for or sponsored it.

## 6. Rollout, cheapest first

### Now: bootstrap, while users arrive through a social web of trust

1. **pubky/inbox first-contact rule.** A ping that opens a new (sender, recipient) pair needs a reverse edge or an invite, vouch or sponsor ticket. Pings within an admitted pair, and replacements, stay free. All five existing layers stay, and the IP limits remain the floor.
   - Ship `first_contact = "open"` as the default, and move the hosted deployment to `"ticket"` once clients support it.
   - Admitted pairs keep sender–recipient edges for longer than pings do. Prune pairs idle for 180 days, and cap the table like every other inbox structure.
2. **Homegate.** Add an endpoint that issues sponsor credentials through the existing verification routes, and mint one alongside each verified signup token. Synonym's inbox trusts the Synonym gate by default.
3. **Homeserver signup.** Signup tokens are single-use bearer codes today: the code is consumed by whichever key signs up with it first (`signup_service.rs`, `mark_as_used`). Pooling them buys homeserver accounts, not first contacts, because inbox admission doesn't rely on them. When Homegate issues a token for a verified request, it should bind the token to the requesting key so that only that key's signup consumes it. That is a small homeserver change (assumption, verify).
4. **One verifier crate** for ticket encoding, verification and the spend table, used by the inbox, with Homegate as the issuing side.
5. **Abuse reports** on ticket-opened pairs, the burn threshold, and per-issuer standing, as described in §4.
6. **Metrics:** first contacts per lane and per issuer; reports per lane and per issuer, as a share of the pairs each opened; burned keys; lane saturation. These numbers decide what gets built next.

### Later: at scale, only when the metrics show the need

7. The PoW lane, Tor-style, active only under load.
8. Third-party gates, including proof-of-UTXO and payment routes, and Nexus as an issuer of `established` attestations.
9. The same ticket check on any new public listener, before it accepts writes from unknown keys.

### Not building

- VDFs.
- Timestamp proofs of identity age.
- Global spam scores.
- Server-side negative reputation for identities or IPs.

## 7. Open questions for the team

1. **Moving the inbox off open first contact** (SeverinAlexB): which apps rely on unsolicited pings today, such as pubky.app chat or the Shop (assumption, verify)? And when should the hosted inbox switch to `"ticket"`?
2. **Sponsor quota and burn threshold:** how many new pairs per day, how many distinct reports burn a key, and what each gate route should cost so that a burned key's pairs cost more than spam is worth. The credential stays bound to the sender key and one deployment. A gate learns which inbox a user uses, but never whom they contact.
3. **Encoding:** the JWS form that Pubky grants and inbox session proofs already use, or a compact binary form? Recommendation: JWS, for reuse.
4. **Vouch source:** only pairs the inbox has admitted, or also public follows read from Nexus or the recipient's homeserver at `/pub/pubky.app/follows/`?
5. **PoW function:** Equi-X (proven in Tor, needs WASM and mobile builds) or SHA-256 (can be outsourced)? And is a miner market wanted at all, given gates?
6. **Defaults for Synonym's inbox:** default issuers and budgets, who operates the gate, and pricing for the paid routes.
7. **Security review** (SHAcollision): domain separation for ticket signatures, bounds on the spend table, the binding between `sub` and the session, and whether reports can be gamed.

Sources, shallow clones of `pubky/*` on 10 Nov 2026: inbox `967ec78`, pubky-homeserver (formerly pubky-core) `c29f540`, pubky-nexus `0125822`; homegate README read through the GitHub API.
