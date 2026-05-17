# M-E2E live transcript: 2026-05-17

This file captures a successful run of `tests/e2e/live_roundtrip.sh` against
the deployed `https://timestamp.inblock.io` aggregator, per the
"Done criteria" section of `docs/success-criteria.md` §M-E2E.

The transcript is the canonical proof-of-life that the full pipeline (SIWE
challenge -> session -> submit -> seal -> witness retrieval -> Merkle
proof verification -> EIP-191 signature recovery + DID isolation 403 +
no-bearer 401) works against the live deployment.

## Provenance

- Date: 2026-05-17
- Service: `https://timestamp.inblock.io` (Docker `aqua-timestamp:latest`
  on `agentic-hub`, behind `portal-caddy-1`).
- Service git ref: `e32f0cb feat(m3): witness revision minter and aqua-node
  compatible /trees endpoints` (M3; EVM/qTSA anchors still stubbed at this
  point per the M3 -> M4 hand-off note in `CLAUDE.md`).
- Client git ref: this commit (M-E2E ladder rung).
- Client host: clawi orchestrator (Ubuntu, Rust 1.85+).
- Test client BIP39 mnemonic: stored only in gnome-keyring under
  `service=aqua-timestamp-test-client user=clawi kind=mnemonic`. The
  wrapper script reads it via `secret-tool` and exports it to the binary
  via `AQUA_TIMESTAMP_TEST_CLIENT_MNEMONIC` (process env only, never on
  disk, never in argv).

## Notes on this run

- `merkle_root == leaf` here because the test submitted a single leaf into
  an otherwise empty epoch. The RFC 9162 root of a 1-leaf tree is the leaf
  hash itself. Inclusion proof for `(leaf_index=0, tree_size=1)` is empty;
  `verify_inclusion` accepts this.
- `signer_recover == server_did address` is the load-bearing assertion:
  the witness Signature revision recovers cleanly to the public service
  identity, end-to-end over TLS.
- The negative-test bearer is minted for a fresh in-process random
  keypair, never persisted, never derived from the keyring entry.
- Stub anchors (M3): `transaction_hash` inside the TimestampObject
  payload is all zeros for both methods, and the EVM
  `smart_contract_address` is also zero. This will change when M4 lands;
  the assertion code does NOT look at the anchor result fields, only the
  Merkle proof + signature, so the same transcript continues to pass.

## Transcript

```
probing https://timestamp.inblock.io/health ...
OK   /health = 200

aqua-timestamp e2e :: live
base_url = https://timestamp.inblock.io
[step 1] OK   derived test client did:pkh:eip155:1:0x5d6055694d98B5Bb888c3E51eC39877e927e0501 (0x5d6055694d98B5Bb888c3E51eC39877e927e0501)
[step 2] OK   identity shape ok, server_did=did:pkh:eip155:1:0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f
[step 3] OK   auth/challenge signed and POST /auth/session returned a token
[step 5] OK   generated random leaf 0x9b567514c32154b6872e6d4be74268e84f58e7dc011b191a6fdf89e5d628a62e
[step 6] OK   submitted leaf to epoch 5 (closes_at=1778995495)
[step 7] OK   /v1/schedule confirms epoch 5 sealed
[step 8] OK   retrieved 2 witness revisions for leaf 0x9b567514c32154b6872e6d4be74268e84f58e7dc011b191a6fdf89e5d628a62e
[step 9] OK   L1 ok: every revision JSON re-hashes to its declared link
[step 9] OK   L2 ok: inclusion proof verifies (root=0x9b567514c32154b6872e6d4be74268e84f58e7dc011b191a6fdf89e5d628a62e, idx=0, size=1)
[step 9] OK   L3 ok: EIP-191 signature recovers to 0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f (== server_did address)
[step 10] OK   negative-1 ok: foreign DID (did:pkh:eip155:1:0x89Da7351bB5def3396567113F83775faa24ACde1) gets 403 on by-leaf
[step 10] OK   negative-2 ok: no-bearer POST /v1/leaves returns 401

------ e2e summary ------
base_url       = https://timestamp.inblock.io
server_did     = did:pkh:eip155:1:0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f
client_did     = did:pkh:eip155:1:0x5d6055694d98B5Bb888c3E51eC39877e927e0501
epoch_id       = 5
leaf           = 0x9b567514c32154b6872e6d4be74268e84f58e7dc011b191a6fdf89e5d628a62e
merkle_root    = 0x9b567514c32154b6872e6d4be74268e84f58e7dc011b191a6fdf89e5d628a62e
object_hash    = 0xc2902153fb63a8aa46e2748b3e5ea11734eabd31b87bdaae76cf8087e83eaf85
signature_hash = 0x83c3097f8d4da344552491d8d528f1974aa12717a16ff8b56dda8976c278cf32
signer_recover = 0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f
STATUS         = OK
```

## Reproduce

```sh
# From the repo root, on the clawi orchestrator host:
tests/e2e/live_roundtrip.sh
# Or override the target:
BASE_URL=https://timestamp.inblock.io tests/e2e/live_roundtrip.sh
```

`exit 0` means every assertion in the flow held. Any nonzero exit means
the first failing step is in the script's stderr / stdout.
