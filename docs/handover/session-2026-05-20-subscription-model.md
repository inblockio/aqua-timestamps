# Handover: Subscription Model for Wallet Rate Limits

## Context

The fuel bonding curve (v0.2.0-draft) governs the macro allocation: what
percentage of incoming fuel goes to anchoring (A) vs operations (B). The
smart contract enforces this split on-chain.

This handover concerns the **micro allocation**: how the service distributes
its finite timestamping capacity across individual wallets. The subscription
model is the missing layer between "the anchoring wallet has funds" and
"wallet X is allowed to submit Y hashes per day."

## What we know (from prior sessions)

These seed constraints were established during the fuel curve design:

- Number of new wallets that can register is limited
- Maximum hashes per wallet per day is capped
- Hash rate allocation scales with the wallet's fuel contribution
- **1 hash/second is free** with a starting epoch config of **10 minutes**
- Fuel contribution is tracked per wallet

## What needs designing

### 1. Free tier definition

The "1 hash/second free at 10-minute epoch" statement needs unpacking:

- Does "1 hash/second" mean 1 hash submitted per second (burst rate), or
  1 hash per second averaged over the epoch?
- Is the free tier per wallet, per DID, or per IP?
- What happens when a free-tier wallet exceeds its allowance? Queued?
  Rejected? Deprioritized in the Merkle tree?
- Is the free tier permanent or a bootstrap incentive that phases out?

### 2. Paid tier mechanics

Wallets that contribute fuel get higher hash rate allocation:

- What is the function mapping fuel contribution to hash rate? Linear?
  Logarithmic (matching the fuel curve's character)?
- Is contribution measured as lifetime total, rolling window, or per-epoch?
- Does the contribution go to the same intake wallet as the fuel curve, or
  a separate "subscription" address?
- How does this interact with the smart contract? The contract governs the
  macro split; does it also track per-wallet contributions, or is that
  off-chain (Aqua-on-Aqua)?

### 3. Capacity model

The service has a finite anchoring budget (determined by the publication
rate curve). The subscription model must allocate this capacity:

- Total hashes per epoch = f(anchoring balance, gas cost, publication rate)
- Per-wallet allocation = g(wallet's contribution, total contributions,
  free tier guarantee)
- What happens when total demand exceeds capacity? Fair queuing?
  Priority by contribution? First-come-first-served within tiers?

### 4. Registration limits

- Why limit wallet registration at all? Anti-sybil? Capacity planning?
- Is the limit global (e.g., 1,000 wallets total) or rate-limited (e.g.,
  10 new wallets per epoch)?
- How does a wallet register? SIWE auth already exists (M1). Is
  registration just "first SIWE from a new DID"?
- Can wallets be deregistered? By the wallet owner? By the operator?

### 5. Interaction with existing systems

| System | Interaction |
|---|---|
| **Fuel bonding curve** | Subscription consumes the anchoring budget that the curve allocates. The curve is the macro layer; subscription is micro. |
| **Publication rate curve** | Determines total anchoring capacity per epoch. Subscription divides this capacity across wallets. |
| **Smart contract** | Does per-wallet contribution tracking live on-chain or off-chain? On-chain is transparent but expensive. Off-chain (Aqua-on-Aqua) is cheaper but needs the trust competition model for accountability. |
| **SIWE auth (M1)** | Already gates API access per DID. Subscription extends this with rate limits per DID. |
| **Trust competition model** | If the operator unfairly allocates capacity, the service gets forked. This is the enforcement backstop for off-chain subscription accounting. |

### 6. Economic design questions

- Is the subscription model "fuel, not fee"? (It should be, per project
  principles.) If so, how does "contribute fuel to get higher hash rate"
  differ from "pay a fee for service"? The distinction matters for
  messaging and for the trust competition model.
- Does the subscription model create lock-in? It should not (forkability
  principle). A wallet's contribution history should be portable or
  re-provable on a forked service.
- How does this interact with the founder reward? The founder reward
  activates at max publishing rate on both chains. Does subscription
  demand factor into "max publishing rate"?

## Suggested approach for next session

1. Start with the capacity model (item 3). It sets the hard ceiling that
   everything else must fit within.
2. Define the free tier precisely (item 1). This is the base case.
3. Design the contribution-to-rate function (item 2). Keep it simple;
   logarithmic is the natural choice given the fuel curve's character.
4. Resolve on-chain vs off-chain tracking (item 5). This is the biggest
   architectural decision.
5. Registration limits (item 4) and economic framing (item 6) can follow.

## Related documents

- `Spec_Aqua_L1_Operational_Fuel_Bonding_Curve.md` (v0.2.0-draft)
- `Spec_Aqua_L1_Timestamping_Bonding_Curve.md` (publication rate curve)
- `Spec_Aqua_Trust_Competition_Model.md` (forkability as governance)
- `docs/handover/session-2026-05-20-fuel-curve-design.md` (prior session)
