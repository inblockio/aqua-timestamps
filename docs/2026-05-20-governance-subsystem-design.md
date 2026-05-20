# Governance Subsystem Design

**Date:** 2026-05-20
**Status:** Approved design, ready for implementation planning
**Scope:** Institutional trust root via founder wallet, governance tree,
bootstrap protocol

## Foundational Principle

> Every instruction is a signed message. An unsigned instruction carries
> no identity, no accountability, and no basis for verification; it is
> not a legitimate operation. The network operating system enforces this:
> nothing executes without a signature.

This principle governs the entire governance subsystem. No unsigned data
enters the trust store. No unauthenticated session uploads governance
artifacts.

## Overview

The governance subsystem establishes the institutional trust root for an
aqua-timestamp deployment. It introduces two concepts:

1. **Founder wallet**: a cold root authority whose public key is the
   trust anchor for all delegation. The private key never touches the
   service. The founder uses it externally (via aqua-cli) to sign
   governance artifacts.
2. **Authorization key**: an operational key (analogous to an SSH key)
   that authenticates CLI sessions to the server. The founder delegates
   upload authority to this key by configuring it at boot.

The governance tree is an Aqua tree built and signed externally by the
founder, uploaded once via an authenticated CLI session, persisted
permanently in fjall storage, and served at
`GET /.well-known/aqua-governance`.

## Roles and Key Hierarchy

```
Founder key (cold, external, root trust)
  Three jobs only:
    a) Declare/authorize keys (trust delegation)
    b) Receive 1% success reward (beneficiary)
    c) Authoritative org smart contract interactions

  Delegates to:
    Authorization key (hot, operational, like SSH key)
      - Authenticates CLI sessions to the server
      - Uploads founder-signed governance artifacts

    Publishing wallet (hot, operational) [FIXME LATER]
      - Reviews and operates proposals
      - Day-to-day governance operations

    Service identity key (already exists)
      - Runs the timestamp service
      - Signs witnesses, identity tree, SIWE challenges
```

The founder key is the only key that can populate the trust store. All
other keys derive their authority from a signed declaration by the
founder.

## Founder Key Properties

- **Public key only in service.** Private key lives outside (hardware
  wallet, cold storage, air-gapped machine).
- **Beneficiary.** Receives the 1% success reward from the fuel split.
- **Rotation (FIXME LATER).** The founder can rotate the key once. The
  new key then has the same one-rotation allowance. Rotation is anchored
  to the org smart contract, which is the central trust primitive.
  Depends on the contract existing.

## Boot Configuration

Two addresses must be set before first boot. No governance data in
config; all governance content comes from the founder-signed tree.

```toml
[governance]
founder_address = "0x..."   # EIP-55. Trust root. First signed config
                            # file must come from this address.
auth_address    = "0x..."   # EIP-55. Operational upload key.
                            # Authenticates CLI sessions.
```

Both are required. The service refuses to start without them.

## Service States

### Un-bootstrapped

- `[governance]` config is set (founder + auth addresses known)
- No governance tree has been ingested yet
- `GET /.well-known/aqua-governance` returns `404`
- Core timestamping still works (accumulator, sealer, anchors)
- The service is operationally functional but institutionally unanchored

### Bootstrapped

- Governance tree has been ingested and persisted
- `GET /.well-known/aqua-governance` serves the tree
- Founder address is read from the tree (cross-checked against config)
- Contract addresses, beneficiary, trust declarations are available

## Bootstrap Protocol

```
Founder (external):
  1. Builds governance tree using aqua-cli
     - genesis revision: founder DID, service identity cross-ref
     - contract declarations: timestamping + governance addresses
     - beneficiary declaration: 1% reward recipient address
  2. Signs the tree with founder key (EIP-191)

Operator (CLI session):
  3. Connects to server via CLI
  4. Authenticates with auth_address (SIWE key-signing challenge)
  5. Uploads the signed governance tree

Service:
  6. Verifies CLI session is authenticated by auth_address
  7. Verifies governance tree is signed by founder_address
  8. Cross-checks: tree's founder DID matches config founder_address
  9. Both checks pass: ingest into fjall, persist permanently
  10. Service transitions to "bootstrapped" state
  11. GET /.well-known/aqua-governance now serves the tree
```

Two signatures, two verification steps, both required. The auth key
proves "I am allowed to talk to this server." The founder signature
proves "this governance data comes from the root authority."

## Governance Tree Structure

The tree is an Aqua tree (same `{revisions, file_index}` shape as
`/trees/*` responses). Built externally by the founder via aqua-cli.

### Revision types

**`governance_genesis`** (root revision)
- Founder DID: `did:pkh:eip155:{chain_id}:0x{founder_address}`
- Service identity DID cross-reference
- Timestamp of creation
- Signed by founder key

**`contract_declaration`** (chained to genesis, one per contract)
- Contract type: `timestamping` or `governance`
- Contract address + chain ID
- Signed by founder key

**`beneficiary_declaration`** (chained to genesis)
- Beneficiary address for the 1% success reward
- Initially equals founder address (can diverge later via governance)
- Signed by founder key

**`trust_declaration`** (chained to genesis) [FIXME LATER]
- Authorized key DID
- Role: `publishing_wallet`, `operator`, etc.
- Signed by founder key
- Requires the proposal/review flow (governance decision rounds)

All revisions use the SDK's `create_object_util` + EIP-191 signature
pattern. The founder signs externally; the service only verifies.

**Template hash enforcement (TODO).** The service must hardcode the
expected template hashes for each governance revision type
(`governance_genesis`, `contract_declaration`, `beneficiary_declaration`,
`trust_declaration`). On ingestion, every revision's template hash is
checked against this allowlist. Unknown template hashes are rejected.
The exact template definitions and their hashes must be defined in
aqua-sdk (or derived from it) before implementation.

**Migration path: template registry.** The hardcoded allowlist is the
bootstrap phase. The migration target is a template registry populated
by the signed governance config tree itself. The founder can declare
new template hashes as governance revisions (signed, verified against
founder address), and the service adds them to the accepted set. This
lets the system accept new revision types without a binary upgrade.
The registry is itself a governance artifact: unsigned template
additions are rejected.

## Storage

New fjall partition:

- **`governance_tree`**: stores the complete governance Aqua tree as
  serialized JSON. Single key (`governance`) mapping to the full tree.
  Overwritten only when a new governance tree is ingested (future:
  rotation, new declarations).

The governance tree is small (a handful of revisions). No pagination,
no per-revision partitioning needed.

## Endpoints

### `GET /.well-known/aqua-governance`

- **Un-bootstrapped:** returns `404`
- **Bootstrapped:** returns the governance Aqua tree in the same
  `{revisions, file_index}` shape as `/trees/*`
- **No authentication required.** This is public, verifiable data.

### `POST /v1/governance/bootstrap`

- **Authentication:** SIWE challenge-response with `auth_address`
- **Body:** the founder-signed governance Aqua tree (JSON)
- **Verification:**
  1. Session authenticated by auth_address
  2. Tree signed by founder_address
  3. Founder DID in tree matches config founder_address
- **Response:** `201 Created` on success
- **Idempotency:** if already bootstrapped, returns `409 Conflict`
  (future: a separate update endpoint for governance tree amendments)

## Governance Decision Flow [FIXME LATER]

When the service matures beyond key declarations:

- Governance decisions follow the agent audit trail pattern
  (proposal, review, approval as signed Aqua revisions)
- Each governance round aligns with the BTC difficulty epoch (~2 weeks)
- The publishing wallet (delegated by founder) reviews and operates
  within each round
- All decisions are signed messages; unsigned proposals are rejected

This is not in scope for the first implementation.

## Trust Model and Security Assumptions

- **Server trust assumed.** If the server is compromised, software keys
  are exposed regardless. This is acknowledged as a maturity path, not
  a day-one fortress.
- **Founder key is the root.** Its compromise is catastrophic but
  mitigated by: cold storage, minimal usage (three jobs only), future
  rotation capability via org contract.
- **Auth key is replaceable.** If compromised, reconfigure and restart.
  It grants upload access, not governance authority.
- **Flexibility to grow.** The design supports adding HSM-backed keys,
  threshold signing, and contract-based governance without breaking the
  bootstrap model. Each upgrade narrows the trust surface without
  requiring a redesign.

## What's Deferred

| Item | Depends on |
|---|---|
| Trust declaration upload flow | Proposal/review flow design |
| Governance decision rounds (2w BTC epochs) | Publishing wallet delegation |
| Contract state reading (replaces config) | Org smart contract deployment |
| Key rotation (once per key) | Org smart contract |
| Publishing wallet delegation | Trust declaration flow |
| Governance tree amendments/updates | Update endpoint design |

## Relationship to Other Subsystems

- **Identity tree** (`/.well-known/aqua-identity`): describes what the
  service is. Governance describes who controls the institution. Separate
  concerns, separate trees, separate endpoints.
- **Fuel/bonding curve**: the beneficiary address from the governance
  tree is where the 1% reward flows. The governance tree is the
  authoritative source for this address.
- **Audit trails** (`/agent-audit`): governance decisions will follow
  the same pattern when the proposal/review flow is implemented.
- **Key security pathway**: the HSM/Vault upgrade path from
  `analysis_2026-05-20_key-security-upgrade-path.md` applies to the
  auth key and service key. The founder key is managed externally.
