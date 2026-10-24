# aqua-timestamp-e2e

End-to-end client for the aqua-timestamp aggregator (OpenWitness). OW1.5, audit item E.

## What the main path asserts

Sign in with the standing identity, submit the tip of a fresh one-file client tree, wait for
the seal, then fetch BOTH witnesses of the leaf (`/trees/by-leaf/{leaf}?method=evm` and
`?method=qtsa`), merge both witness pairs into the client tree and run the SDK verifier
(`Aquafier::verify_tree_sync`) on it. Asserted per method: the timestamp revision carries no
verifier error, its anchor reached the verified state (EVM verdict `Verified`; qTSA token
admitted with its facts on the live reader), the aggregator signature revision carries no
error and is signed by the identity document's `server_did`, and the whole tree verifies. The
two anchors must cover the same root. No check is re-implemented here.

Failures: a qTSA (or EVM) 404; a stub (empty or zero transaction hash, a `stub` marker, a
method/network mismatch); a 202 still pending at `--witness-timeout-secs` (default 1200, the
error names the pending method; 202 is polled because EVM is served only at finality); any
other status; a malformed body.

## Standing identity

One secp256k1 identity, created once and never rotated or overwritten by the test:

```
~/.local/state/openwitness-seal-e2e/   0700   (--identity-dir / OPENWITNESS_E2E_IDENTITY_DIR)
  secp256k1.key   0600   private key, hex
  identity.json   0600   {"alias":"openwitness-seal-e2e","did":...,"key_type":"secp256k1","created_at":...}
```

A group- or world-accessible directory or key, a record naming another DID, or a key without a
record (or the reverse) is refused, not repaired. ed25519 and p256 have no standing identity:
those clients exist only in `selfcheck-all`, in-process, with ephemeral keys. The foreign-DID
403 check also needs a second random identity and runs in-process only.

## Commands

```
aqua-timestamp-e2e live --base-url <URL> [--identity-dir D] [--seal-wait-secs 1500]
                        [--witness-timeout-secs 1200] [--evm-rpc-url URL]
aqua-timestamp-e2e selfcheck [--identity-dir D]      # in-process aggregator, offline doubles
aqua-timestamp-e2e selfcheck-all
```

`--base-url` (or `OPENWITNESS_E2E_BASE_URL`) has no default and is printed. The production host
(`openwitness.org`, any subdomain) is refused unless `--allow-production`; that run belongs to
OW2 / SP3.

## What `selfcheck` proves and what it does not

The aggregator runs in-process on `127.0.0.1` with the core crate's simulated chain and TSA as
anchors, and the reader asks those same doubles (the server binary has no such mode). So it
proves the whole flow over HTTP (identity loading, auth, submit, seal, both witnesses, merge,
the SDK verifier incl. batch inclusion, template checks, signature) and that a reader whose
chain or TSA does not know the anchors fails the run. It does not prove a real chain
transaction, a real RFC 3161 token or the EU trust list (the simulated TSA reports no token
facts, so the "token admitted" check is only enforced on the live reader), nor EVM finality
timing. Real-token and honest-chain verification are covered by
`aqua-timestamp-core/tests/witness_sdk_verify.rs`.
