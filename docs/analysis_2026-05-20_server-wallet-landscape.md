# Analysis: Server Wallet and HSM Landscape for secp256k1

**Date:** 2026-05-20
**Context:** Evaluating hardened, audited, minimal server wallets with optional HSM for aqua-timestamp's secp256k1 signing key.
**Decision:** Self-hosted HashiCorp Vault + vault-plugin-secp256k1 as the planned upgrade path, deferred until traction.

## Evaluation Criteria

1. Minimal / small codebase and attack surface
2. Hardened for server-side use
3. Third-party security audit
4. HSM capable (YubiHSM, PKCS#11, cloud KMS)
5. Runs without HSM (software-only fallback)
6. secp256k1 support (Ethereum + Bitcoin compatible)

## Tier 1: Building Blocks (Rust)

### alloy-signer ecosystem
- **Repo:** github.com/alloy-rs/alloy (monorepo)
- **License:** MIT / Apache-2.0
- **Chains:** Ethereum and all EVM chains. secp256k1 signing is curve-compatible with Bitcoin.
- **Backend crates:**
  - `alloy-signer-local`: software keys via k256. Feature flags: `keystore`, `mnemonic`, `yubihsm` (YubiHSM 2 built in)
  - `alloy-signer-aws`: AWS KMS (`ECC_SECG_P256K1`)
  - `alloy-signer-gcp`: GCP Cloud KMS (`ec-sign-secp256k1-sha256`)
  - `alloy-signer-ledger` / `alloy-signer-trezor`: hardware wallets
- **Audit:** Underlying k256 crate audited by NCC Group (two high findings, both corrected). 5.7M+ downloads.
- **Minimalism:** Each crate is small. `alloy-signer` is just the trait definition.
- **Assessment:** Best fit for aqua-timestamps. ~50-100 lines of integration on top of existing code.

### RustCrypto k256
- **Repo:** github.com/RustCrypto/elliptic-curves/tree/master/k256
- **License:** MIT / Apache-2.0
- **Audit:** NCC Group (two high findings, corrected)
- **Performance:** ~1.8x slower signing than libsecp256k1 C; fine for server signer.
- **Assessment:** Lowest-level building block. Start here for a 500-line signing daemon.

## Tier 2: Minimal Signing Daemons

### tmkms (Tendermint KMS)
- **Repo:** github.com/iqlusioninc/tmkms (~360 stars)
- **License:** Apache-2.0
- **Language:** Rust
- **HSM:** YubiHSM 2 (PKCS#11 / direct USB), Fortanix DSM. Feature-gated at compile time.
- **Software fallback:** `softsign` feature for file-based encrypted keys.
- **secp256k1:** Yes (k256 v0.13).
- **Audit:** One audit, one low-severity finding.
- **Codebase:** ~5-10k lines Rust, single binary.
- **Maturity:** Production since 2019, Cosmos validator ecosystem.
- **Limitation:** Tendermint-specific wire protocol. Reusable HSM abstraction layer, but needs adaptation for Ethereum tx signing.
- **Assessment:** Closest existing Rust code to "minimal hardened signing daemon with HSM".

### iqlusion ethereum_hsm_signer
- **Repo:** github.com/iqlusioninc/ethereum_hsm_signer
- **License:** Apache-2.0
- **Language:** Rust (same team as tmkms)
- **Assessment:** HSM signer via gRPC for Ethereum. Appears proof-of-concept / early stage. Check activity before depending on it.

### ConsenSys Web3Signer
- **Repo:** github.com/Consensys/web3signer (~254 stars)
- **License:** Apache-2.0
- **Language:** Java (JDK 21+)
- **HSM:** Azure Key Vault, HashiCorp Vault, encrypted keystores.
- **secp256k1:** Native.
- **Audit:** Internal ConsenSys Diligence only. No public external audit report found.
- **Codebase:** 30-50k+ lines Java, heavy dependency tree.
- **Assessment:** Production standard for Eth validators, but the opposite of minimal. Overkill for single-key signing.

## Tier 3: Vault Plugins

### vault-plugin-secp256k1 (Pelipas)
- **Repo:** github.com/pelipas/vault-plugin-secp256k1
- **Origin:** Fork of kaleido-io/vault-plugin-secrets-ethsign, made blockchain-agnostic.
- **Language:** Go (HashiCorp Vault plugin)
- **Features:** `/signRaw` endpoint for raw ECDSA secp256k1 signatures. Works for Bitcoin, Ethereum, any secp256k1 chain.
- **HSM:** Inherits Vault Enterprise HSM seal (PKCS#11) for key encryption at rest.
- **Software fallback:** Vault's encrypted storage.
- **Audit:** No public third-party audit.
- **Assessment:** Most minimal "sign arbitrary data with secp256k1 from Vault" option.

### kaleido-io/vault-plugin-secrets-ethsign
- **Repo:** github.com/kaleido-io/vault-plugin-secrets-ethsign
- **License:** Apache-2.0
- **Assessment:** Ethereum-specific parent of the Pelipas fork. Generates keys, stores in Vault, exposes `/sign`.

### immutability-io/vault-ethereum
- **Repo:** github.com/immutability-io/vault-ethereum
- **Assessment:** Full Ethereum wallet in Vault. More features, correspondingly larger. PGP-signed, no public audit.

## Tier 4: MPC / Threshold Signing

### LFDT-Lockness/cggmp21
- **Repo:** github.com/LFDT-Lockness/cggmp21
- **License:** MIT / Apache-2.0
- **Language:** Rust, `no_std` compatible
- **Audit:** Kudelski Security (report at docs/audit_report.pdf). Only audited Rust CGGMP21 under permissive license.
- **Origin:** Dfns, donated to Linux Foundation Decentralized Trust.
- **Assessment:** Gold standard for future t-of-n threshold ECDSA needs.

### Fystack/mpcium
- **Repo:** github.com/fystack/mpcium (~100+ stars)
- **Language:** Go
- **Chains:** ETH, BTC, BNB, Polygon, Solana, 10+.
- **Deployment:** Docker Compose, systemd, K8S.
- **Assessment:** Most complete open-source self-hosted MPC wallet. Go-based.

## Tier 5: Enterprise SaaS (not recommended)

- **Cubist CubeSigner:** Rust internals, AWS Nitro + KMS, Veridise audit. SaaS only.
- **Turnkey:** TEE-based, ex-Coinbase Custody team. SaaS only.
- **BitGo:** Multi-sig + MPC. SaaS only. Notable prior vulnerability disclosure.

## Cloud KMS secp256k1 Support

| Provider | Key Spec | Status |
|---|---|---|
| AWS KMS | `ECC_SECG_P256K1` | Most battle-tested. Must handle DER-to-ETH sig conversion, EIP-2 s-value normalization, v-bit recovery. |
| AWS CloudHSM | Via PKCS#11 | Known verification bug on EL6 (use EL7+). |
| GCP Cloud KMS | `ec-sign-secp256k1-sha256` | Non-deterministic nonce. Can sign Keccak256 digests. |
| Azure Key Vault | `P-256K` / `SECP256K1` / `ES256K` | SDK naming inconsistency. |
| YubiHSM 2 | Native PKCS#11, USB, HTTP connector | FIPS 140-2 Level 3. ~$650/device. |
| Thales Luna | Native PKCS#11 | FIPS 140-2/3 Level 3. Enterprise pricing. |

## Decision

**Selected path:** Self-hosted HashiCorp Vault + vault-plugin-secp256k1 on DigitalOcean.

**Rationale:**
- No cloud dependency (fits self-hosted infrastructure)
- Key never in application memory
- Vault audit log for signing operations
- Software-only (no physical HSM purchase needed initially)
- Localhost signing (no cross-cloud latency)

**Deferred until:** Service gains traction. Current env-var key storage is acceptable for testnet/early production.

**Fallback:** YubiHSM 2 (~$650) with alloy-signer-local `yubihsm` feature if Vault operational overhead proves too high.
