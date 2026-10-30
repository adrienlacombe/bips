```
  BIP: ?
  Layer: Applications
  Title: QSB Wallet Secret Management
  Authors: Adrien Lacombe <6303520+adrienlacombe@users.noreply.github.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: CC0-1.0
  Version: 0.1.0
```

## Abstract

This proposal specifies deterministic derivation, identification, disclosure control, and recovery metadata for wallets holding the hash-based signing secrets used by Quantum Safe Bitcoin (QSB). It defines the `QSB-HORS-v1` derivation profile and a portable recovery manifest. It separates recovery of secret material from recovery of one-time-use state, and defines requirements for wallets that release selected preimages to a transaction assembler.

This is an application-layer proposal. It changes neither Bitcoin consensus nor relay policy, and does not standardize or establish the security of the QSB transaction construction. Its initial profile targets the two-round, 150-commitment-per-round construction used by the QSB Ledger application. Other constructions require separately specified profiles.

## Copyright

This proposal and its original auxiliary code are placed in the public domain under CC0-1.0.

## Motivation

A QSB wallet has two distinct kinds of authority: ordinary Bitcoin keys used for funding, helper inputs, or authentication, and HORS preimages used to authorize a vault spend. Backing up an ordinary Bitcoin key does not necessarily back up those preimages. Conversely, a helper signature does not prevent a party holding sufficient HORS material from constructing a different vault spend.

Independent implementations need to agree on which seed bytes enter derivation, domain labels, integer encodings, commitment ordering, and recovery metadata. Without this agreement, restoring the same seed in another wallet can produce different commitments or leave funds undiscovered.

Deterministic derivation creates an additional problem: every restored copy of a seed can reproduce secrets that another copy has already disclosed. Neither a seed nor an unspent blockchain output proves that a secret set remains unused. A failed or abandoned withdrawal may already have disclosed preimages to an untrusted host. This proposal therefore treats disclosure history as persistent wallet state, independent of transaction confirmation.

## Specification

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be interpreted as described in RFC 2119 and RFC 8174 when written in capitals.

### Scope and conformance

This proposal defines two explicit conformance claims:

* **Derivation-compatible**: implements the seed, secret, commitment, and commitment-root algorithms below and passes their vectors. This claim provides no assurance about disclosure state or transaction verification.
* **Custody-conforming**: is derivation-compatible and implements all applicable lifecycle, manifest, disclosure, and recovery requirements below. Software wallets and hardware wallets may both make this claim.

A product MUST identify which claim it makes. Neither claim means that a withdrawal's transaction-to-HORS-subset relationship has been independently verified by a signing device. The trust boundary for that verification MUST be disclosed separately.

This proposal does not assign APDU instruction numbers, PSBT fields, descriptor syntax, a seed mnemonic format, or an encrypted backup container. It defines the semantics that such transports and containers must preserve.

### Terminology and encodings

`S` is the wallet's master seed byte string. `K` is the QSB derivation key. `net` is a one-byte derivation namespace; `v` is a vault index; `r` is a zero-based round; `i` is a zero-based secret index. A **vault key set** is the complete collection of 300 secrets for one `(K, net, v)`.

All literal strings used in cryptographic computations are ASCII bytes without an implicit terminator. `||` denotes concatenation; slices use zero-based, end-exclusive bounds. `u8`, `u16be`, and `u32be` denote fixed-width unsigned integers of one, two, and four bytes; multi-byte integers are big-endian. Hash outputs are raw bytes, not hexadecimal strings. `HASH160(x) = RIPEMD160(SHA256(x))`.

These encodings apply only to this proposal's derivation and records. Bitcoin transaction serialization retains its own encoding rules.

### Seed source and key separation

For a BIP-39 wallet, `S` MUST be the 64-byte binary seed obtained by the BIP-39 seed-generation procedure, including its UTF-8 NFKD normalization and optional passphrase. It MUST NOT be the mnemonic's entropy, mnemonic text, a BIP-32 private key, an extended key, or a wallet signature.

A wallet MAY instead use an independently generated 32-byte seed from a cryptographically secure random generator. The recovery manifest MUST identify the seed source as `bip39` or `raw32`; other seed sources require a future specification. A wallet MUST NOT silently reinterpret one source as another.

New seeds generated specifically for this profile MUST contain at least 256 bits of random entropy. Existing valid BIP-39 seeds MAY be imported; doing so does not increase their original entropy. Human-chosen passwords MUST NOT be used directly as seeds. Passphrase handling and backup remain properties of the seed format.

Derive `K` using SLIP-0021 at the single label `QSB-HORS`:

```text
M = HMAC-SHA512(key = ASCII("Symmetric key seed"), msg = S)
N = HMAC-SHA512(key = M[0:32], msg = 0x00 || ASCII("QSB-HORS"))
K = N[32:64]
```

This is a single SLIP-0021 child, not a BIP-32 path. Hardware APIs may use their own output-buffer layout; implementations MUST obtain the mathematical key defined above, rather than assume an API exposes the complete node.

The key `K` MUST NOT be used as an ordinary Bitcoin signing key, encryption key, or authentication credential. It MUST NOT be exported through routine wallet-host commands. Seed backup and deliberate recovery are distinct from routine commands. Ordinary funding and helper keys use their existing Bitcoin wallet standards and MUST NOT serve as inputs to QSB secret derivation.

### QSB-HORS-v1 derivation profile

The profile identifier is the exact string `QSB-HORS-v1`. Its parameters are:

| Parameter | Value |
| --- | --- |
| Production network namespace | `net = 0x00`, Bitcoin mainnet |
| Test namespace | `net = 0x01`, shared testing only |
| Vault index | `0 <= v < 2^31` |
| Rounds | `r = 0, 1` |
| Secrets per round | `i = 0, ..., 149` |
| Secret length | 20 bytes |
| Commitment length | 20 bytes |
| Disclosure cardinality | 8 distinct indices in round 0; 7 in round 1 |

Round `r = 0` is the first digest round, which the QSB paper and the existing device documentation call round 1; `r = 1` is the second.

Namespace `0x01` preserves the existing implementation's test convention. It does not distinguish testnet, signet, and regtest. Test deployments MUST coordinate indices across all of those chains under the same seed, or use separate seeds. This proposal defines no production custody profile for those chains. Other namespace bytes MUST be rejected.

For each valid tuple:

```text
m = ASCII("QSB-HORS-v1") || 0x00 || u8(net) || u32be(v) || u8(r) || u16be(i)
s[v][r][i] = HMAC-SHA256(key = K, msg = m)[0:20]
c[v][r][i] = HASH160(s[v][r][i])
R[v] = SHA256(ASCII("QSB-HORS-v1/root") ||
              c[v][0][0] || ... || c[v][0][149] ||
              c[v][1][0] || ... || c[v][1][149])
```

The message `m` is exactly 20 bytes. Truncation takes the first 20 HMAC output bytes. No integer reduction, curve operation, additional hash, or per-secret randomness is permitted. Invalid parameters MUST be rejected before derivation.

`R` is a flat hash of ordered commitments, not a Merkle root and not a Bitcoin script hash. For human comparison a wallet MAY display the first eight bytes as four groups of four lowercase hexadecimal digits. Automated matching MUST use all 32 bytes. The fingerprint is not an authentication mechanism.

No account component exists in this profile. User accounts, labels, and ordinary Bitcoin derivation paths MUST NOT alter these equations. A new profile that changes secret generation MUST use new cryptographic domain labels. Merely changing a manifest's profile name does not create fresh secrets.

### Allocation and script association

For each seed and namespace, a wallet MUST maintain an allocation high-water mark `next_v`. Allocating a vault reserves the current index and durably increments `next_v` before publishing commitments for use in a deposit. An index reserved for a deposit MUST NOT be reused, even if the deposit is cancelled. At `next_v = 2^31` allocation fails; it MUST NOT wrap.

Read-only derivation of commitments is permitted without allocation, but MUST NOT present the result as safe to fund. A wallet MUST NOT knowingly fund the same vault key set twice, whether in one transaction, in different transactions, or under different script templates. Reuse of the same key set under a new script version is still reuse. Funds sent to a vault script by any party after its key set is exposed require a different `T` and therefore cannot be withdrawn under custody conformance. A wallet SHOULD NOT present an exposed vault's script as a deposit destination and SHOULD warn users not to reuse one.

Before presenting an output as an owned QSB vault, the trusted wallet component MUST validate its supported script template and compare every embedded commitment, in the template-defined order, with the derived commitments. It MUST compute and retain `SHA256(scriptPubKey)` separately from `R`. A template match alone proves neither ownership nor safe allocation. The actual `scriptPubKey`, amount, and outpoint MUST be checked against the funding transaction before disclosure.

The script template and consensus validation remain the responsibility of a QSB implementation. This proposal does not make arbitrary scripts valid or safe merely because they contain matching commitments.

### Disclosure lifecycle

Each allocated key set has one of these states:

* `allocated`: reserved, with a trusted continuous history establishing that no disclosure has been authorized.
* `exposed`: a disclosure request has been durably committed; some, all, or none of its bytes may have reached the host.
* `retired`: no further disclosure is permitted.
* `unknown`: history is missing, stale, conflicting, or cannot be established as continuous.

Confirmation and funding status are separate metadata. They MUST NOT reset disclosure state. A fresh seed starts with an empty allocation history. An imported seed MUST NOT automatically be treated as fresh.

An `allocated` set may transition to `exposed` after authorization, or to `retired`. An `exposed` set may only be retried as specified below or become `retired`. Any uncertainty causes `unknown`; recovery from that state requires trustworthy history, not user dismissal of a warning. A `retired` set remains retired. Confirmation of the disclosed transaction is not by itself a reason to retire an `exposed` set; a wallet SHOULD retain the exact retry so that a reorganization cannot strand funds.

No individual secret may be released before the authorized request and its `exposed` transition are durably recorded. A crash after recording but before returning a response therefore consumes the authorization. Torn writes and unreadable records MUST fail closed. Implementations MUST serialize concurrent requests so that two different requests cannot both pass an unused-state check.

Storage exhaustion MUST cause refusal of further disclosures or allocations requiring new records. Implementations MUST NOT forget an exposed entry and subsequently treat its key set as unused. Compaction is permitted only if it preserves the same refusal behavior, for example by permanently retiring an entire index range.

### Disclosure requests and retries

A custody-conforming wallet accepts exactly eight distinct indices from round 0 and seven distinct indices from round 1, all in `[0,149]`. Index order is significant and MUST be preserved; indices MUST NOT be sorted automatically. The same numeric index in different rounds denotes different secrets and is allowed. Bonus puzzle selections that do not reveal HORS secrets are not extra entries in these arrays.

The request MUST include the complete proposed spending transaction structure and all previous-output information needed to verify amounts, scripts, and fees. Define `T` as the Bitcoin legacy serialization of that transaction after setting every input's scriptSig to the empty byte string and omitting all witness data. Keep the version, ordered outpoints, sequences, ordered outputs, and locktime unchanged. `T` is not a PSBT serialization and its hash is not necessarily the final transaction ID.

Define:

```text
B = SHA256(T)
I = u16be(round0[0]) || ... || u16be(round0[7]) ||
    u16be(round1[0]) || ... || u16be(round1[6])
D = SHA256(ASCII("QSB-HORS-v1/reveal") || I || B)
```

The record is scoped by the actual seed context, profile, namespace, and vault index, and stores the full `R`, script hash, ordered indices, `B`, and `D`. A short wallet fingerprint MUST NOT be the sole authority for selecting another seed's record. The wallet MUST derive `B` itself from the parsed transaction. Accepting a caller-supplied hash alone does not satisfy this requirement.

A transaction MAY spend more than one vault. Each vault has its own request, record, and user authorization; the same `T` combined with a different `I` yields a different `D`, and the retry rules apply to each record separately.

The user MUST authorize release after seeing the network, vault identifier, disclosure cardinality, destination outputs and amounts, and total fee. Displayed transaction values MUST be computed from the supplied transaction and verified previous transactions. If the trusted secret-holding component does not verify the QSB puzzle and the link from the transaction to the requested indices, it MUST prominently identify the operation as disclosure of spending secrets with an **unverified transaction binding**. It MUST NOT describe it as a verified signature authorizing only the displayed destination. Custody conformance permits this explicit trust model; it does not repair that verification gap.

An implementation offering verified transaction binding MUST independently validate the QSB solution, supported script, transaction digest calculations, and requested HORS indices inside the claimed trusted boundary. A helper-input signature, a supplied binding hash, or matching commitments is insufficient evidence of this verification. This proposal does not specify that verifier's algorithm.

The response contains only the requested preimages, in round-0 order followed by round-1 order. The recipient MUST verify each preimage against its indexed commitment. No API may disclose arbitrary additional indices, an entire set, or `K` as a convenience for transaction assembly.

After a timeout, crash, failed broadcast, or lost response, another disclosure is permitted only when the entire persisted authorization matches: seed context, profile, namespace, index, root, script, ordered indices, and `T`. A fresh user authorization is REQUIRED for a new session. Chunk retries within a live approved session MAY be idempotent. Ending a session MUST clear transient approval, without clearing the persistent record.

Reordering an input or output, changing the destination, amount, fee, sequence, or locktime, or requesting any different index sequence MUST be refused after exposure. Completing input signatures for the same `T` does not change `B`. Fee replacement requiring a different `T` is not a retry. Because `T` cannot change after exposure, a fee can be raised only by means that leave `T` unchanged, such as a child transaction spending one of its outputs; wallets SHOULD choose the fee with that constraint in mind before requesting disclosure. No cancellation, mempool eviction, chain reorganization, or absence of an on-chain spend restores unused status.

### Host and solver boundaries

Commitments and scripts MAY be sent to a solver. The seed, `K`, and unrevealed preimages MUST NOT be sent to a solver or service for search, simulation, or recovery. Search interfaces SHOULD accept commitments without private material.

Selected preimages become spending-sensitive data when released, before broadcast or confirmation. A host, assembler, or service receiving them is within the disclosure trust boundary. Wallets MUST avoid putting them in analytics, logs, crash reports, URLs, clipboard automation, or generic diagnostic exports. Implementations SHOULD minimize their lifetime in memory and use appropriate zeroization facilities; managed runtimes MUST NOT claim guaranteed erasure when they cannot provide it.

Transport encryption does not make an untrusted recipient safe. Any claim of resistance to a future quantum attacker must also account for the transport and backup cryptography; it is not supplied by this derivation profile.

### Portable recovery manifest

The manifest is a UTF-8 JSON object with the exact schema below. Object member order and whitespace are insignificant. Duplicate member names, unknown members, invalid UTF-8, trailing data, and non-integral numeric values MUST be rejected. This version has no extension fields; extensions require a new format version. Hex strings use lowercase hexadecimal without a prefix. Integers have the ranges stated here; none exceeds the exact integer range of common JSON implementations.

Top-level members, all required:

| Member | Type and meaning |
| --- | --- |
| `format` | String `qsb-secret-manifest` |
| `version` | Integer `1` |
| `profile` | String `QSB-HORS-v1` |
| `seed_source` | `bip39` or `raw32` |
| `network` | String `bitcoin-mainnet`; maps to derivation namespace `0x00`. This version carries no test-namespace state; such state is not portable |
| `next_v` | Integer in `[0, 2^31]`, the next unallocated index |
| `vaults` | Array of records sorted by ascending `v`, with no duplicate indices |

Each vault record has exactly these members:

| Member | Type and meaning |
| --- | --- |
| `v` | Integer in `[0, next_v)` |
| `root` | 32-byte commitment root as 64 hex characters |
| `script_pubkey` | Full script bytes as hex, or `null` if no script was finalized |
| `script_hash` | SHA-256 of those bytes as 64 hex characters, or `null` together with the script |
| `funding` | `null`, or object with exactly `txid` (64 hex characters in conventional displayed txid order), `vout` (unsigned 32-bit integer), and `value_sat` (integer in `[0,2100000000000000]`) |
| `state` | `allocated`, `exposed`, `retired`, or `unknown` |
| `disclosure` | `null`, or object with exactly `round0`, `round1`, `transaction`, and `digest` |

The disclosure arrays follow the cardinality, range, and ordering rules above; `transaction` is `T` as hex; `digest` is `D` as 64 hex characters. The transaction MUST parse completely, have empty scriptSigs, and have no witness serialization. Exactly one input of `T`, the vault input, MUST have the outpoint `funding`; `funding.txid` is in displayed order, so its bytes are reversed relative to the hash serialized in `T`. An exposed record requires non-null script, funding, and disclosure. An allocated record requires null disclosure. Retired and unknown records preserve any available disclosure; a non-null disclosure always requires non-null script and funding. Non-null funding requires a non-null script. Scripts MUST be nonempty and no longer than 10,000 bytes, and MUST be recognized by the importing wallet before use. Resource limits MAY cause an explicit import refusal, never truncation.

Missing indices below `next_v` are permanently reserved and unavailable for allocation or disclosure. This permits compact representation of cancelled or retired allocations without marking them fresh. An export MUST include every active vault and every exposed vault for which retry is retained. It MUST retain roots, script bytes, and funding data needed to recover active funds. Imported manifests MUST preserve all known exposed or retired information and MUST NOT lower a locally established high-water mark.

Before accepting a record, the importer MUST recompute its root from the seed, recompute its script hash, check the supported script and commitments, recompute any disclosure digest, and check any claimed funding output against the actual previous transaction before use. Null values permit incomplete historical records to be preserved but do not authorize funding or disclosure.

The manifest contains no seed, `K`, passphrase, or preimages. It is privacy-sensitive wallet metadata. A checksum is neither authentication nor evidence of freshness. The manifest format deliberately defines no trusted `fresh` flag; trust in an imported history comes from the recovery procedure, not an assertion inside JSON.

### Backup, restoration, and multiple devices

A recoverable backup consists of both the seed backup, including any required BIP-39 passphrase, and the current manifest with trustworthy disclosure history. Seed-only recovery can regenerate commitments, but cannot by itself establish safe allocation or disclosure state. The user MUST be informed of that distinction before the wallet accepts funding.

Manifests MUST be updated durably before allocation is published and before any preimage is returned. An external backup that is unavailable or stale MUST NOT be represented as a current recoverable history. Implementations MAY keep local protected state and replicated journals, but MUST specify which loss or rollback events invalidate their continuity guarantee.

On restoration, all imported allocated or exposed records MUST be treated as `unknown` for further disclosure unless the wallet has a trustworthy way to establish that the history is complete and current. Authenticated but old backups do not suffice. A current manifest must be tied to a protected continuity mechanism, such as a surviving authoritative wallet journal with enforced exclusive ownership. A seed, root match, user assertion, service response, or blockchain scan alone is insufficient. This proposal does not specify an acceptable continuity mechanism. Until one is specified, recovery after loss of the authoritative writer is expected to proceed through the emergency path described below, outside custody conformance.

When trustworthy continuity cannot be established, the wallet MAY recover public data and display balances, but MUST refuse new disclosures and reuse of that seed's allocation namespace under custody conformance. New deposits require a fresh independent seed. This restriction can prevent spending funds after loss of state; it is an explicit availability tradeoff. An emergency tool that bypasses it MUST identify the operation as outside custody conformance, and MUST NOT erase or relabel the uncertainty.

Two devices containing the same seed MUST NOT independently allocate or disclose from this namespace. Implementations MUST enforce a single authoritative writer or a coordination mechanism providing atomic allocation and disclosure decisions. A handoff MUST transfer the current history and disable the previous writer before enabling the replacement. Copying a seed or merging two ordinary backup files does not accomplish a safe handoff.

On merging records, exposed or retired information MUST never be weakened. Different disclosures for the same key set, different scripts or roots for the same index, or uncertain writer history cause an `unknown` state and refusal. A larger `next_v` is retained, but choosing the maximum alone does not establish safe continuity.

Secret-bearing backups for legacy randomly generated vaults require authenticated encryption and an independently specified portable container; they MUST NOT be included in this manifest. Password strength and backup encryption are separate security properties, and this proposal introduces no password KDF or encryption algorithm.

## Rationale

**SLIP-0021 rather than BIP-32.** A symmetric derivation path avoids coupling HORS secret recovery to an elliptic-curve private key, signature, or vendor-specific key export. Preserving the existing label makes the profile usable across vendors without changing already-derived commitments.

**SLIP-0021 rather than BIP 85.** BIP 85 derives application entropy from a BIP-32 root key at a hardened path and is the established Bitcoin standard for that purpose. It was not chosen because the existing implementation already derives from the SLIP-0021 label, because SLIP-0021 is a purely symmetric construction that needs no elliptic-curve arithmetic in the secret-holding component, and because the Ledger operating system derives SLIP-0021 keys natively. A BIP 85 profile would produce different commitments and would need its own domain labels.

**Fixed parameters rather than a configurable framework.** Secret length, commitment order, and index encoding are interoperability requirements. Allowing implementations to select them independently would make a profile identifier insufficient for recovery. Other parameter sets need new profiles and domain separation.

**Twenty-byte secrets.** This length matches the existing implementation; it is not a recommendation for new hash-based signature designs and does not imply 128-bit post-quantum security. A longer seed cannot raise the security ceiling imposed by the commitment function or transaction construction.

**256-bit seed entropy.** Public commitments allow offline guessing of seeds and passphrases, and a quantum adversary roughly halves the effective entropy of that search. A 128-bit seed would then sit below the preimage ceiling of the 160-bit commitment, making the seed the weakest link; 256 bits keeps it above that ceiling without raising the ceiling itself.

**One committed disclosure rather than a counter of confirmed spends.** Secret exposure happens at release, not mining. Even if a particular HORS construction tolerates some repeated usage under a specified analysis, this proposal does not rely on such a bound. Exact retries preserve usability without authorizing additional secret material or a changed transaction. The single-disclosure rule is a policy choice stricter than any reuse bound the QSB analysis may support; a future profile could relax it only with an explicitly specified bound. It is also why a fee-replacement transaction is refused after exposure.

**State as part of recovery.** Determinism recovers keys but also reproduces old authority. Recording a reveal before returning it handles local crashes; it cannot stop a seed clone or an old backup from reproducing that reveal elsewhere. The specification makes that limitation explicit rather than treating a service's duplicate-root database as a cryptographic guarantee.

**Transport neutrality.** APDU sizes, USB framing, and host libraries are product choices. Standardizing the derivation and persistent semantics allows different devices and software wallets to recover the same vault without requiring one vendor's wire protocol.

## Backward Compatibility

Derivation and commitment-root bytes match `app-qsb` at commit `e8fc8ea68292d4c7dcda2f848d8caf3d4edfb028`. Existing vaults derived by that algorithm retain their secrets and commitments. The test namespace remains shared for compatibility.

The existing device protocol's reveal digest is byte-compatible when its caller-supplied binding equals the `B` defined here. This proposal additionally fixes the binding serialization and requires the wallet to compute it. Existing requests are not presumed to satisfy that stronger requirement.

The inspected implementation allows eviction of old reveal records, loses device-local history across reset or reinstall, and displays transaction details supplied by the host without verifying their relationship to the requested subset. It is a derivation reference, not a custody-conforming reference implementation. Adopting this proposal requires changes to persistent state, recovery handling, authorization, and host integration. Existing histories of uncertain completeness import as unknown.

Randomly generated legacy preimages cannot be recreated from a seed by assigning a vault index. Their original encrypted secret backups MUST be preserved until the funds are spent and no recovery need remains. Migration to this profile requires spending into a new output with newly derived commitments; changing metadata does not migrate on-chain funds.

No ordinary Bitcoin wallet seed, path, address, PSBT, or transaction format is changed by this proposal. An ordinary seed-compatible wallet that does not implement this profile cannot be assumed to recover QSB vaults.

## Security Considerations

Compromise of `S` or `K` exposes all vault secrets in this profile. Domain separation does not isolate vaults after root-key compromise. Public commitments enable an attacker to check guessed seeds or passphrases offline. New high-entropy seeds and strong seed-backup practices remain necessary.

Commitments and roots can be derived for any index without authorization, so a host that can query the trusted component can enumerate every vault of a seed and link them on chain. Unauthenticated commitment export is convenient for deposit flows but has that privacy cost; this profile does not require approval for it, and products should weigh the tradeoff.

HORS secrets have one-time-use constraints that ordinary ECDSA wallet interfaces do not express. Reusing a vault root, permitting additional index disclosures, rolling back history, or interpreting an unspent output as unused can invalidate the intended security model. Reorganizations must never roll back disclosure records.

A malicious host may request the subset for an unintended transaction. Recording a binding prevents subsequent conflicting requests; it does not prove the first request is correct. Full transaction-to-subset verification is a separate requirement for a wallet claiming verified withdrawal authorization. Likewise, a public commitment root is not proof of seed ownership, history freshness, or transaction validity.

This BIP provides no numerical unauthorized-spend bound for QSB. Security depends on the concrete Bitcoin script, transaction binding, hash functions, parameters, attacker resources, and every stage that handles disclosed preimages. It does not establish safety of funding inputs already vulnerable to a quantum adversary or of the destination output after withdrawal.

Loss of authoritative history can make a custody-conforming wallet refuse to spend. This failure mode must be considered when designing backups and device upgrades. No purely deterministic seed derivation can prove that another copy has not already disclosed a secret.

## Reference Implementation and Test Vectors

The accompanying [reference implementation](bip-qsb-wallet-secrets/reference.py) implements the derivation primitives and digest encoding. [Test vectors](bip-qsb-wallet-secrets/vectors.json) supply deterministic public test fixtures. These values are for testing only and MUST NOT be used to hold funds. The code does not implement a production wallet, secure storage, the manifest importer, or a QSB transaction verifier.

For `K = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`:

```text
net=0, v=0, r=0, i=0
s = df83cf4950602d2d3b90041023b941271bc7c494
c = 887b040fb41eb3cf514e3bd63986f08697b943c4

net=0, v=0, r=1, i=149
s = 84f94456b5537fc0a7b922e056673e455d666c0a
c = 27567ff92caad5adb3484d58f93e4995262d78df

R(net=0,v=0) = 9b257b6acd00017b1488ed9d73d05bc8a5dbdd43c8aa54d1d37c7e807d65c515
R(net=0,v=7) = 8ea0f0b0ac0db4db0405bedf47bd3c54fe946e5d1ed3a158fb11a72580940e11

round0 = [0,1,2,3,4,5,6,7]
round1 = [140,141,142,143,144,145,146]
B = abababababababababababababababababababababababababababababababab
D = 498b1ea9b6c381e78fc76f0a9c2003b1d29ef25caf92d5a3b6a1d7dbc90f7d2c
```

The last fixture tests digest encoding only; it does not assert that the arbitrary `B` is the hash of a valid spending transaction. Additional vectors cover seed-to-key derivation from a stated mnemonic and passphrase, network separation, index boundaries, and a binding derived from a serialized transaction together with its digest.

Custody implementations MUST additionally test: durable-record failure before release; power loss after recording but before response; partial response and exact retry; changed transaction or index order; duplicate and out-of-range indices; corrupt and full storage; reset and stale-backup restoration; duplicate JSON members and inconsistent manifest data; conflicting writers; unknown profiles; allocation exhaustion; and a reorganization after disclosure. No such event may silently make an exposed key set fresh. A complete lifecycle reference implementation and independent interoperability testing remain prerequisites to advancing this proposal to Complete.

## References

* [BIP 3: Updated BIP Process](https://github.com/bitcoin/bips/blob/master/bip-0003.md)
* [BIP 39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
* [SLIP-0021: Hierarchical derivation of symmetric keys](https://github.com/satoshilabs/slips/blob/master/slip-0021.md)
* [QSB research repository](https://github.com/avihu28/Quantum-Safe-Bitcoin-Transactions)
* [QSB-HORS-v1 derivation implementation](https://github.com/starknet-innovation/app-qsb/blob/e8fc8ea68292d4c7dcda2f848d8caf3d4edfb028/qsb-core/src/hors.rs)
* [Existing device protocol and limitations](https://github.com/starknet-innovation/app-qsb/blob/e8fc8ea68292d4c7dcda2f848d8caf3d4edfb028/docs/apdu.md)
* [Existing derivation and guard vectors](https://github.com/starknet-innovation/app-qsb/blob/e8fc8ea68292d4c7dcda2f848d8caf3d4edfb028/qsb-core/src/tests/hors.rs)
* [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
