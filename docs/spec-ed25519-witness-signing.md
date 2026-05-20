# Spec: Ed25519 Witness Signing

## Signature Performance

| Curve | Sign | Verify | Seal cost/leaf (2 sigs) |
|---|---|---|---|
| secp256k1 (EIP-191) | ~1 ms | ~0.5 ms | 2.0 ms |
| Ed25519 | ~60 us | ~170 us | 0.12 ms |

Ed25519 is ~17x faster to sign and ~3x faster to verify. At seal time,
signing drops from 88% of per-leaf cost to 32%; JSON serialization
becomes the new floor.

## Security Considerations

- **Key isolation.** The root secp256k1 key (service identity, on-chain
  anchor signer) stays cold. A hot Ed25519 key handles high-frequency
  witness signing. Compromise of the hot key is a rotation, not an
  identity loss.
- **Curve strength.** Both curves offer ~128-bit security. Ed25519
  uses a rigid (non-manipulable) curve; secp256k1's Koblitz structure
  has no known weakness but is a less conservative choice
  cryptographically.
- **Rotation.** Swapping the Ed25519 key requires only a new delegation
  claim signed by the root key. The service DID is unchanged.

## Delegation Template (upstream gap)

The SDK (`aqua-rs-sdk`) lacks a delegation claim template. Required
fields:

| Field | Type | Purpose |
|---|---|---|
| `delegated_key_did` | string | Ed25519 DID receiving authority |
| `authority_scope` | string | e.g. `"witness_signing"` |
| `valid_from` | u64 | Unix timestamp |
| `valid_until` | u64 / null | Unix timestamp or open-ended |

The delegation revision is signed by the root secp256k1 key and
published in the identity tree at `/.well-known/aqua-identity`.

Until the SDK ships this template, hand-assemble the revision (same
pattern as `service_claim_server`). File upstream issue on
`aqua-rs-sdk`.
