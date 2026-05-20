# Analysis: Key Security Upgrade Path for aqua-timestamp

**Date:** 2026-05-20
**Context:** Planning the progression from current env-var key storage to production-grade key isolation.
**Status:** Deferred, activate when service gains traction.

## Current State

The service identity is a single secp256k1 key derived from a BIP-39 mnemonic. It serves as:
- EIP-191 signer (identity tree, witness signatures)
- Sepolia anchor key (on-chain timestamp transactions)
- SIWE challenge signer

The mnemonic lives in gnome-keyring on the operator's machine, deployed to the server via `/root/timestamp/.env` (chmod 600, not in git). The application reads `AQUA_TIMESTAMP_ANCHOR_MNEMONIC` once at boot, derives the private key, and holds it in `Arc<String>` inside `ServiceIdentity`. The `Debug` impl redacts it.

**Risk profile:** Key material is in application process memory for the service lifetime. A memory dump, core file, or container escape exposes the key. Acceptable for testnet with limited funds, not acceptable for mainnet with real value.

## Upgrade Phases

### Phase 0: Current (env-var, in-process key)

- **Trigger:** Now
- **Key location:** Application memory
- **Signing:** In-process via aqua-rs-sdk `Secp256k1Signer`
- **Risk:** Medium. Key in memory, but server is single-tenant, SSH-only access.
- **Cost:** $0

### Phase 1: Self-hosted Vault (software isolation)

- **Trigger:** First paying customer or mainnet anchor
- **Architecture:**
  ```
  aqua-timestamp --> localhost:8200 --> HashiCorp Vault
                                          vault-plugin-secp256k1
                                          encrypted key in /vault/data
  ```
- **Key location:** Vault's encrypted storage, decrypted only inside Vault process
- **Signing:** HTTP call to Vault `/sign` endpoint over localhost
- **What changes in aqua-timestamp:**
  - New `VaultSigner` implementing the signing trait
  - Config gains `[signing.vault]` block (url, token/approle, key name)
  - `ServiceIdentity` switches from in-process key to Vault-backed signer
  - Existing `Secp256k1Signer` stays as fallback (config toggle)
- **Operational overhead:**
  - Vault container in docker-compose
  - Unseal procedure after restart (Shamir shares or auto-unseal)
  - Vault audit log rotation
- **Risk:** Low. Key not in application memory. Vault process is separate trust boundary.
- **Cost:** $0 (Vault OSS is free, plugin is open source)

### Phase 2: Physical HSM (hardware isolation)

- **Trigger:** Significant transaction volume or compliance requirement
- **Architecture:**
  ```
  aqua-timestamp --> alloy-signer-local (yubihsm feature) --> YubiHSM 2 (USB)
  ```
- **Key location:** YubiHSM 2 hardware. Key never leaves the device.
- **Signing:** USB/PKCS#11 call to the HSM
- **What changes in aqua-timestamp:**
  - Replace `VaultSigner` or add `HsmSigner` alternative
  - Config gains `[signing.yubihsm]` block (connector URL, auth key ID)
  - alloy-signer-local with `yubihsm` feature added to Cargo.toml
- **Risk:** Very low. Key is hardware-bound.
- **Cost:** ~$650 per YubiHSM 2 device (one-time)

### Phase 3: Threshold signing (no single point of compromise)

- **Trigger:** Multi-party governance requirement or regulatory pressure
- **Architecture:** 2-of-3 threshold ECDSA via cggmp21
- **Key location:** Shares distributed across independent signers (separate servers, operators, or HSMs)
- **What changes:** Significant. Signing becomes a multi-round protocol. Epoch sealing latency increases.
- **Risk:** Lowest. No single compromise reveals the key.
- **Cost:** Infrastructure for 3 signer nodes + operational coordination

## Integration Points in aqua-timestamp

The signing key is used in three places:

1. **Identity tree construction** (`crates/aqua-timestamp-core/src/identity.rs`): Signs the `service_claim_server` revision at boot.
2. **Witness minting** (`crates/aqua-timestamp-core/src/witness.rs`): Signs each witness revision at seal time.
3. **EVM anchor** (`CliEthTimestamper`): Signs Sepolia transactions. This one is hardest to move to Vault because the SDK's `CliEthTimestamper` constructs its own signer internally from the mnemonic.

For Phase 1, items 1 and 2 are straightforward (replace `Secp256k1Signer` with `VaultSigner`). Item 3 requires either:
- A custom `TimestampProvider` that uses Vault for transaction signing (bypassing `CliEthTimestamper`)
- Or contributing an alloy-signer backend to aqua-rs-sdk's `CliEthTimestamper`

## Recommendation

Start Phase 1 when either condition is met:
- First mainnet anchor (real ETH at stake)
- First external customer (service trust requirement)

Until then, the current env-var approach is proportionate to the risk. Document the upgrade path so it can be executed in a single session when needed.
