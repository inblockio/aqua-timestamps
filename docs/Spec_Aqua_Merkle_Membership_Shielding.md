# Spec: Merkle Membership Shielding

**Date:** 2026-05-20
**Scope:** aqua-rs-sdk (breaking protocol change)
**Status:** Draft v2, post core-developer review

## Problem

Standard Merkle inclusion proofs leak sibling hashes. At least one
sibling in every proof is a raw leaf hash submitted by a different
user. This enables a membership inference attack: an attacker who
holds their own proof can confirm whether a suspected hash was
submitted to the same epoch.

This is not a content leak (Aqua revision hashes are opaque). It is
a membership leak: the ability to confirm that a specific hash was
timestamped in a specific batch.

Full exploitation analysis: `docs/attack_vector_merkle_proof_sibling_leak.md`.

## Solution

Before inserting a leaf into the batch Merkle tree, compute a
shielded value:

```
shielded = H(leaf_bytes || nonce_bytes)
```

Then apply RFC 6962 domain separation:

```
merkle_leaf = H(0x00 || shielded)
```

where:

- `H` is the hash function identified by the tree's `HashType`
  (currently `Sha3_256`, with `Blake3_256` on the SDK roadmap).
- `leaf_bytes` is the raw 32-byte revision hash submitted by the
  client (decoded from `0x`-prefixed hex).
- `nonce_bytes` is a cryptographically random 32-byte value generated
  server-side per leaf (decoded from `0x`-prefixed hex).
- `||` denotes byte concatenation.
- `0x00` is the single-byte leaf domain separation prefix per
  RFC 6962 Section 2.1.

The Merkle tree is built over `merkle_leaf` values. Proofs contain
shielded-and-domain-separated siblings that cannot be reversed
without the per-leaf nonce, which only the corresponding submitter
holds.

## Three-concern decomposition

The SDK uses Merkle trees for two distinct purposes, each with its
own privacy/integrity requirements. Three orthogonal mechanisms
address three distinct threats:

| Concern | Mechanism | Threat addressed | Scope |
|---------|-----------|------------------|-------|
| Node-type confusion | RFC 6962 domain separation (`0x00` leaf, `0x01` internal) | Second-preimage: a crafted leaf that collides with an internal node (or vice versa) | All Merkle trees in the SDK |
| Membership inference | Shielding: `H(leaf \|\| nonce)` | Sibling hash in proof reveals another user's raw leaf hash | Batch timestamp Merkle trees only |
| Field-level privacy | HKDF salt derivation (`derive_prk`, `derive_field_salt`) | Selective disclosure: redacted fields must be unlinkable without the revision nonce | Selective disclosure Merkle trees only |

These are independent. Removing domain separation would break both
batch and selective disclosure trees. Removing shielding would
re-expose sibling hashes. Removing HKDF would break selective
disclosure. Each addresses a different threat class.

The full batch timestamp leaf computation is therefore two stages:

```
Stage 1 (shielding):       shielded    = H(leaf_bytes || nonce_bytes)
                           input: 32 + 32 = 64 bytes

Stage 2 (domain sep):      merkle_leaf = H(0x00 || shielded)
                           input: 1 + 32 = 33 bytes
```

Both stages use the tree's `HashType`. There is no separate
"shielding algorithm" configuration.

## Hash independence property

The submitted leaf's original hash algorithm is independent of the
tree's `HashType`. A leaf computed with SHA3-256 can be shielded and
inclusion-proven in a Blake3 tree. The service treats submitted
leaves as opaque 32-byte values. The shielding function and tree
construction both use the epoch's configured `HashType`.

This is a deliberate design choice: one configuration knob
(`HashType`) governs both shielding and tree construction. There is
no separate "shielding algorithm" concept.

## Leaf ordering

Leaves are inserted in **submission order**. The tree is constructed
on the fly as new members join; there is no sort pass after
collection. `batch_leaf_index` is the zero-based position in
submission order.

This is normative. Implementations MUST NOT sort leaves before tree
construction.

The aqua-rs-sdk is authoritative for Merkle tree construction and
verification. Consuming services (aqua-timestamps, etc.) MUST
produce trees that the SDK can verify.

## Verification flow

1. Verifier holds: `leaf` (the `previous_revision` of the timestamp
   revision), `shielding_nonce`, `merkle_proof`, `merkle_root`,
   `batch_tree_size`, `batch_leaf_index`, and the tree's `HashType`.
2. Decode `leaf` and `shielding_nonce` from `0x`-prefixed hex to raw
   bytes (32 bytes each).
3. Compute `shielded = H(leaf_bytes || nonce_bytes)` using the tree's
   `HashType`.
4. Compute `merkle_leaf = H(0x00 || shielded)` (RFC 6962 domain
   separation).
5. If `batch_tree_size == 1`: verify `merkle_leaf == merkle_root`
   (decoded to bytes).
6. If `batch_tree_size > 1`: verify the RFC 9162 inclusion proof
   using `merkle_leaf` at position `batch_leaf_index` against
   `merkle_root`.
7. Check that `merkle_root` matches the on-chain anchor (EVM tx or
   qTSA response).

The witness payload is self-contained: it carries the nonce and all
proof data, so any holder of the full witness revision can verify
independently. An observer who only sees another user's shielded
sibling cannot reverse it without that user's nonce.

## Template change

This is a **breaking change**. The existing `timestamp_base.json`,
`timestamp_evm.json`, and `timestamp_tsa.json` schemas are replaced,
not versioned alongside. Old witnesses minted before this change
become invalid under the new template hashes. This is accepted;
batch timestamping is not yet in production.

### Schema change

Add to `timestamp_base.json`, `timestamp_evm.json`, and
`timestamp_tsa.json`:

```json
"shielding_nonce": {
  "type": "string",
  "pattern": "^0x[0-9a-fA-F]{64}$",
  "description": "Per-leaf random nonce for membership shielding. Hex-encoded, 0x-prefixed, 32 bytes."
}
```

`shielding_nonce` MUST be in the `required` array of all three
templates. `additionalProperties` remains `false`.

The `pattern` constraint enforces the exact wire format: `0x` prefix
followed by exactly 64 hex characters (32 bytes). This catches
malformed nonces at schema validation time rather than at Merkle
verification time.

### Rust struct change

In the corresponding Rust payload structs (`EvmTimestampPayload`,
`TsaTimestampPayload`, and any base payload struct):

```rust
pub shielding_nonce: String,
```

Not `Option<String>`. Every witness payload carries a nonce. There
is no unshielded code path under the new template.

### Template hash

The template hash is content-addressed. Changing the schema changes
the hash. This is the intended mechanism: consumers route on
template hash to determine the verification path.

All three templates (`timestamp_base`, `timestamp_evm`,
`timestamp_tsa`) will get new hashes. The `derives_from` and
`ancestry` fields in child templates must be updated to point to
the new base hash. Run `cargo run --bin verify-templates --features
native -- --fix` after modifying the JSON files.

## What changes

| Layer | Change |
|-------|--------|
| Template schemas | `shielding_nonce` added to properties and required (base + EVM + TSA) |
| Rust payload structs | `shielding_nonce: String` field added |
| Merkle tree input | Built over `H(0x00 \|\| H(leaf \|\| nonce))` instead of `H(0x00 \|\| leaf)` |
| Inclusion proofs | Siblings are shielded + domain-separated values, not raw hashes |
| Verification | Must compute `H(leaf \|\| nonce)` then `H(0x00 \|\| result)` before walking proof |

## What does NOT change

| Layer | Detail |
|-------|--------|
| Anchor layer | EVM tx and qTSA call still anchor the Merkle root |
| Witness structure | Still `client_leaf -> TimestampObject -> Signature` |
| Signature | Still EIP-191 over canonical pre-signature JSON |
| DID isolation | Unchanged at the API layer |
| Submitted leaves | Still opaque 32-byte revision hashes |
| HashType selection | Determined by tree configuration, not by this spec |
| Domain separation | `0x00`/`0x01` prefixes per RFC 6962 remain unchanged |
| Selective disclosure | HKDF salt derivation is a separate concern, unaffected |
| Leaf ordering | Insertion order (no sorting); unchanged from current SDK behavior |

## Constraints

- **SDK is authoritative over spec.** The template change MUST land
  in `aqua-rs-sdk` first. Do not bypass `additionalProperties: false`
  with local hacks.
- **Shielding hash MUST use the tree's `HashType`.** Implementations
  MUST NOT hardcode a hash algorithm independently of the tree.
- **Domain separation MUST be applied after shielding.** The
  `merkle_leaf` is `H(0x00 || shielded)`, not `shielded` directly.
  Omitting the `0x00` prefix violates RFC 6962 and PCA-0001.
- **Nonce MUST be cryptographically random.** 32 bytes from a CSPRNG.
  Predictable or reused nonces defeat the shielding.
- **Nonce MUST be returned to the submitter.** It is their secret for
  verification. Without it, the proof is unusable.
- **Nonce wire format MUST be `0x`-prefixed hex.** Pattern:
  `^0x[0-9a-fA-F]{64}$`. Exactly 66 characters.
- **Leaves MUST NOT be sorted.** The tree is built in submission
  order. Sorting would prevent on-the-fly tree construction.

## Security analysis

**Closed:** Direct sibling leaf hash disclosure. Siblings are now
`H(0x00 || H(leaf_other || nonce_other))`, which is computationally
infeasible to reverse without `nonce_other`.

**Unchanged:** Epoch size (`batch_tree_size`) and leaf position
(`batch_leaf_index`) remain visible. `batch_leaf_index` is the
submission-order position. This reveals when a leaf was submitted
relative to others in the same epoch but not the leaf's content.

**Unchanged:** Collusion between submitters who share their full
witness payloads (including nonces) can still reconstruct portions
of the tree. Shielding protects against passive observation of proof
siblings, not against active sharing of secrets. This is inherent to
any scheme where the nonce must be in the witness for self-contained
verification.

## Test strategy (for implementers)

- **Unit:** Build a 4-leaf shielded tree, verify each proof, confirm
  no sibling matches any raw leaf hash.
- **Negative:** An attacker who knows `H_other` but not `nonce_other`
  cannot match it against any sibling in their own proof.
- **Round-trip:** Submit leaf, seal epoch, fetch witness, extract
  nonce, compute `H(0x00 || H(leaf || nonce))`, verify inclusion
  against anchored root.
- **Domain separation:** Verify that a shielded value used directly
  (without `0x00` prefix) fails proof verification. Confirms the
  two-stage computation is enforced.

## Files to modify (aqua-rs-sdk)

1. `src/schema/templates/timestamp_base.json` -- add shielding_nonce
2. `src/schema/templates/timestamp_evm.json` -- add shielding_nonce
3. `src/schema/templates/timestamp_tsa.json` -- add shielding_nonce
4. Rust payload structs for EVM and TSA timestamps -- add
   `shielding_nonce: String`
5. `src/core/timestamp/mod.rs` -- accept nonce, compute
   `H(leaf || nonce)` before `batch_leaf_hash`
6. `src/core/verify_common.rs` (`verify_batch_inclusion`) -- extract
   `shielding_nonce` from payloads, compute two-stage leaf
7. Template hash constants -- run `verify-templates --fix` to cascade

## References

- Attack vector analysis: `docs/attack_vector_merkle_proof_sibling_leak.md`
  (in aqua-timestamps repo)
- SDK Merkle primitives: `src/primitives/merkle.rs` (batch_leaf_hash,
  verify_inclusion, merkle_root)
- SDK batch verification: `src/core/verify_common.rs`
  (verify_batch_inclusion)
- SDK batch creation: `src/core/timestamp/mod.rs`
  (batch_timestamp_with_provider)
- SDK HashType: `src/primitives/hash_type.rs`
- PCA-0001: `docs/2026-05-20-PCA-0001-batch-leaf-domain-separation.md`
  (normative predecessor; domain separation is preserved)
