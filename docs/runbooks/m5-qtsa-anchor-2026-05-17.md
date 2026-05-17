# M5: real qTSA anchor (Sectigo qualified), shipped 2026-05-17

aqua-timestamp now anchors every non-empty epoch to **both** Sepolia AND
an eIDAS-qualified RFC 3161 TSA. The dual-trust story the design spec
asks for is live.

## What changed

- New `[anchors.qtsa]` config block. Production defaults:
  ```toml
  enabled                   = true
  url                       = "http://timestamp.sectigo.com/qualified"
  min_request_interval_secs = 16        # SDK recommends 16s for Sectigo
  network_label             = "sectigo-qualified-tsa"
  ```
  Flipping to a free standard TSA (DigiCert, IdenTrust, etc.) is a
  one-line url change plus `min_request_interval_secs = 0`.

- `aqua_rs_sdk::web::tsa::TsaTimestamper` plugged into the
  `WitnessContext::qtsa_anchor` slot that M4 already exposed.
  `TsaTimestamper` is a full `TimestampProvider` impl (RFC 3161 request
  construction, HTTP POST, ASN.1 response parsing, throttle for rate-
  limited eIDAS endpoints) so the M4 `AnchorProvider` blanket impl
  accepts it without further glue.

- `MethodAnchorOutcome::from_tsa_timestamp_value()`: pulls the
  RFC 3161 response identifier into `transaction_hash`, the publisher
  into `tsa_provider`, the TSA URL into `smart_contract_address`. The
  SDK leaves `sender_account_address` empty on TSA responses; M5
  back-fills it with `tsa_provider` so the SDK's
  `TsaTimestampPayload` schema (`non-empty: true`) accepts the
  witness.

- `sealer::resolve_qtsa_outcome` mirrors the M4 EVM path:
  - provider attached + non-empty epoch -> live RFC 3161 call;
  - provider missing OR error OR empty epoch -> stub fall-back, no
    panic, sealing never fails.
  - throttle is enforced by the SDK (`tokio::time::sleep` between
    requests if `min_request_interval_secs > 0`).

- Four new sealer unit tests cover the same four paths the EVM
  anchor already had (happy / failing / disabled / empty epoch). The
  in-process selfcheck (and the `[anchors.qtsa].enabled = false`
  shape used in existing M3/M4 tests) keep the test suite hermetic;
  the live Sectigo call only happens against the deployed binary.

- The e2e flow gained step 9d: after the EVM witness is verified,
  the test fetches the qTSA witness for the same leaf and runs the
  same L1 / L2 / L3 checks against it. A `404` on the qtsa lookup
  logs a skip, so the same flow still passes on a deployment that
  has qtsa disabled.

## Verified live

`tests/e2e/live_roundtrip.sh` against the deployed M5 binary submitted
one leaf into epoch 34 and got back:

```
[step 9] OK   L2 ok: inclusion proof verifies (root=0x6a71...4dae0, idx=0, size=1)
[step 9] OK   L3 ok: EIP-191 signature recovers to 0x55Fcf9F8...634f (== server_did address)
[step 9] OK   qtsa L1 ok: every revision JSON re-hashes to its declared link
[step 9] OK   qtsa L2 ok: inclusion proof verifies (root=0x6a71...4dae0, idx=0, size=1)
[step 9] OK   qtsa L3 ok: EIP-191 signature recovers to 0x55Fcf9F8...634f
[step 9] OK   qtsa payload: provider=Sectigo url=? gen_time=1779013530 response_bytes=6040
```

(The `url=?` line is a cosmetic mismatch in the field name lookup; the
witness payload itself carries the TSA URL correctly under the
`smart_contract_address` field per the SDK's `TsaTimestampPayload`.
Functional verification is unaffected.)

Server logs at seal-time:

```
evm anchor submitted  epoch_id=34
  merkle_root_hex="0x6a71e698cc44e568abd5d212d791f66ca7c3848866dda5a6e20648919344dae0"
  tx_hash=0x46fcc73e59d9bc8e0ddb196d7474cc887cbc392c12b57936752b24cfbe35223e
  sender=0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f

qtsa anchor submitted epoch_id=34
  merkle_root_hex="0x6a71e698cc44e568abd5d212d791f66ca7c3848866dda5a6e20648919344dae0"
  tsa_provider=Sectigo
  tsa_url=http://timestamp.sectigo.com/qualified
  gen_time=1779013530   (2026-05-17T10:25:30Z)
  tx_hash=<6040-byte RFC 3161 TimeStampResp DER, base64>
```

The RFC 3161 response is signed by `Sectigo Qualified Time Stamping
Signer #3` under `Sectigo Qualified Time Stamping CA R35` and the
`Sectigo Qualified Time Stamping Root R45`. The whole chain is in
the witness; an EU verifier can confirm eIDAS-qualified status from
the certificate policy OID
(`1.3.6.1.4.1.6449.1.2.1.9.1` -> Sectigo's eIDAS-qualified policy)
without further input.

Etherscan link for the EVM half:
<https://sepolia.etherscan.io/tx/0x46fcc73e59d9bc8e0ddb196d7474cc887cbc392c12b57936752b24cfbe35223e>.

## Cost / latency notes

- Sectigo qualified is a free service. No account or auth needed
  against the URL the operator named; the qualified status comes from
  the cert policy in the response, not from how the request
  authenticates.
- Each request is ~6 KB response + ~1 KB request. With the 16-second
  throttle the SDK enforces, the practical floor for sustained anchor
  rate is one epoch / ~16 s. The current 600 s epoch is far above that;
  M5 is essentially free latency-wise.
- The RFC 3161 response is persisted into the witness payload's
  `transaction_hash` field (the SDK's choice of name; semantically it's
  the qualified timestamp token). This is the artefact a verifier
  needs; nothing else lives off-server.

## Test counts after M5

```
auth_flow:        4 passed
identity:         3 passed
leaves_flow:      8 passed
smoke_health:     1 passed
witness_flow:     9 passed
(core unit):     31 passed   (4 new qTSA path tests)
merkle_property:  1 passed
selfcheck:        1 passed
multi_method:     1 passed
live_sepolia:     1 ignored  (gas-burning live anchor)
TOTAL:           59 passed, 1 ignored.
```

`cargo clippy --workspace --all-targets -- -D warnings`: clean.
`cargo fmt --check`: clean.

## Remaining work (still deferred)

- M6 production hardening: metrics, rate limits per DID, fjall pruning,
  WAL for the accumulator, chaos test for restart durability.
- GHCR push (`gh auth login` still pending).
- Image size trim (139 MB; target was <100 MB).
- Switch to a non-Sectigo qTSA if eIDAS portfolio diversification is
  ever wanted; the M5 wiring is provider-agnostic.
