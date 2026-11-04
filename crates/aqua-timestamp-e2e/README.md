# aqua-timestamp-e2e

End-to-end client for the aqua-timestamp aggregator (OpenWitness). OW1.5, audit item E.

## What the main path asserts

Check `GET /health` (200) and report `GET /version` (the served revision), sign in with the
standing identity, submit the tip of a fresh one-file client tree, wait for
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

One secp256k1 identity, never rotated or overwritten by the test. **Only a loopback `--base-url`
(`localhost` or a loopback IP) may create it.** Any other `--base-url`, on `live` and on `seal`,
only loads it: a missing identity is refused with an error that says so, and nothing is written,
so a typo in a path cannot mint a second identity on a remote. There is no init command.

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
aqua-timestamp-e2e seal --base-url <URL> [--allow-production] [--identity-dir D] [--run-dir D]
                        [--expect-version REV] [--expect-server-did DID] [--evm-rpc-url URL]
                        # --expect-server-did is required on a non-loopback --base-url
aqua-timestamp-e2e seal-replay <RUN-DIR> --expect-server-did DID [--out D] [--evm-rpc-url URL]
aqua-timestamp-e2e selfcheck [--identity-dir D]      # in-process aggregator, offline doubles
aqua-timestamp-e2e selfcheck-all
```

`--base-url` (or `OPENWITNESS_E2E_BASE_URL`) has no default and is printed.

The live reader's EVM host asks `https://ethereum-sepolia-rpc.publicnode.com` for a `sepolia`
witness. `--evm-rpc-url` (or `OPENWITNESS_E2E_EVM_RPC_URL`) overrides it; any other network
needs the flag, and a network the SDK does not verify is an error, never a pass. (The SDK v8.0.0
host has no endpoints of its own: without one the anchor is `TIMESTAMP_NOT_EVALUABLE`.) The production host
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

## `seal`: the Set Seal v1 reference e2e

Seals one Folder of three signed members through the aggregator, then checks the result with the
SDK only. One live run takes about 23 minutes on openwitness.org (a 10 minute epoch plus EVM
finality). This crate compares SDK outputs and does the byte flips, the HTTP and the SIWE client
signing; no hash, signature check or verdict is its own.

The live part builds two prepared seals over the same Folder, signs in, sends both S as one
`POST /v1/leaves` (the only POSTs of the run are that one and `/auth/session`), waits for the
epoch's seal, and pulls the witnesses and the epoch listing. Then the steps run, on persisted data:

| Step | What it asserts |
|---|---|
| 1 | Both anchors served for S1, `detect_stub` clean on each payload, each served key the SDK link, the evaluator accepts them, the server's DID attests both, the container has 6 revisions |
| 2 | Under a reader policy pinning TSA and EVM: seal `Verified`, both witnesses admitted, set headline `verified` with completeness, integrity and non-suppression `pass`, the attestation reading names the server DID |
| 3 | Under a policy that admits qTSA only: still `Verified`, the EVM witness `NotAdmitted` and listed |
| 4 | Seal 2 with EVM opted out carries one T and reads `Verified`; four probes that build with no timestamp are refused and write nothing |
| 5 | One byte of the qTSA token flipped and relinked: witness `Failed`, seal `NotChecked`, headline `partially_verified`, nothing `fail`. The attestation P removed, altered under its old key, and altered and re-keyed under its recomputed hash (so the SDK itself runs the EIP-191 check): never `Verified`, no attester DID, and a fresh read of the seal is unchanged |
| 6 | `complete_seal` on the persisted prepared state and witnesses is byte-identical to the stored two-step output. Gate 6a is the SDK's own test `sp2_e8_one_shot_and_two_step_byte_identical`, run at the pinned tag: this crate names it and does not copy its deterministic provider |
| 7 | Every witness the identity can read in the epoch is no stub and names the epoch's root. Visible pairs equal 2 x own leaves always; if the epoch holds more leaves than this run's, the coverage is logged as partial with both numbers, no failure |

`/version` before the run must equal `/version` after it; `--expect-version` additionally pins the
revision before anything is posted. A new deploy does not fail the test, a deploy during the run
does. `--expect-server-did` pins the server's DID: it is required on any non-loopback `--base-url`,
with no default in code, and `/.well-known/aqua-identity` must serve exactly that DID before anything
is posted (a remote run with no pin is refused at the start). Step 2 asserts it again; only on loopback
may it be left out, then the served DID is taken and logged. The reader policy is the one of the openwitness.org witnesses (`ReaderPolicy::open_witness`).

Every step writes `step-<n>.log` with its assertion lines and a final `STEP <n> PASS` or
`STEP <n> FAIL <falsifier>`; the run prints `SEAL RUN PASS` or `SEAL RUN FAIL` and exits non-zero on
a failure. The production host needs `--allow-production`.

```
aqua-timestamp-e2e seal --base-url https://openwitness.org --allow-production \
    --run-dir seal-run --expect-version <REV> --expect-server-did <DID>
```

### The run directory

`--run-dir` (default `seal-run-<UTC>` under the working directory; never inside the identity
directory; a directory that already holds a run is refused) holds the client state, the served
bodies byte for byte:

`run.json`, `aqua-identity.json`, `set-folder.json`, `members/m<i>/tree.json`,
`members/m<i>/files/m<i>.txt`, `nonces-<s>.json`, `leaves.json`, `prepared-seal-<s>.json`,
`s1-evm.json`, `s1-qtsa.json`, `s2-qtsa.json`, `fetch-status.json`, `epochs-<N>.json`,
`epoch-<N>-evm.json`, `epoch-<N>-qtsa.json`, `container-<1,2,5a,5a2,6b>.json`, `attestations-*.json`,
`receipts-<s>/m<i>.json`, `step4b/` (empty unless a probe was wrongly accepted), `debug/`,
`step-<n>.log`. No key material.

## `seal-replay <RUN-DIR>`

Runs steps 2 to 7 from a run directory alone. Step 1 built the container the replay re-reads.

`--expect-server-did` is required here too: step 2 compares the persisted server DID with it.

What it needs: the files above except `leaves.json`, `step4b/`, `debug/`, `step-<n>.log` and what a
replay builds anew and does not compare (`container-5a`, `container-5a2`, `container-6b`, the
`attestations-5b-*` and `attestations-6b` documents). A missing or malformed one is an error naming
the file, before any step runs, never a pass. It also needs the EVM host's chain reads. Those are read-only JSON-RPC calls to
`--evm-rpc-url` (default the public Sepolia node), which go over HTTP POST to that RPC URL. TSA
tokens are checked against the embedded EU trust list, with no network.

The RPC must still serve the anchor transaction's receipt. The default node stops serving receipts
of older transactions (seen for a transaction 44,000 blocks old, about 6 days): the replay then
reads `TIMESTAMP_NOT_EVALUABLE: host_unavailable` and fails steps 2, 3 and 6, correctly and without
a false pass. Replay an older run with `--evm-rpc-url` pointing at a node that keeps receipts.

What it does not need and does not do: it loads no identity (it has no `--identity-dir`), opens no
session and contacts no aggregator. A test holds the source of the replay path to that: it may not
name an HTTP client, a token or the identity loaders. Step 7 reads the persisted epoch bodies.

The run directory stays untouched. What a step derives is compared with what the run persisted,
byte for byte, and goes only to `--out` if given; without `--out` nothing is written, the log goes
to stdout. The binary's SDK revision and the run's are both logged. It prints `SEAL REPLAY PASS` or
`SEAL REPLAY FAIL`.

`cargo test -p aqua-timestamp-e2e --test seal` runs `seal` and `seal-replay` offline: the whole live
part against an in-process aggregator on localhost, with the offline doubles as anchors and hosts,
and a TSA double that reports token facts. That proves the flow, the persisted directory and the
steps' logic, not a real chain or a real RFC 3161 token.
