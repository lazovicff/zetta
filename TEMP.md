Zetta × Laso — Pre-launch model validation

**From:** Filip Lazovic · **Date:** 27.09.2026 · **Status: pre-incorporation**

## 1. What Zetta is

Zetta is a privacy-preserving crypto neobank, in development and not yet launched. Users hold a USD-stablecoin balance and spend it through virtual prepaid cards and payouts. Deposits are on-chain and privacy-preserving (ZK proof-of-burn, EIP-7503 design). Balances and spend authorization live in our off-chain ledger; users authorize card loads and withdrawals with Schnorr signatures from their own keys. A mobile-first UX on card management and
private deposits.

**What is private.** The link between a user and Zetta never appears on-chain. A deposit is an ordinary ERC-20 transfer from the user's wallet to a fresh, unattributable address — indistinguishable from paying any new wallet. Payouts come from our operational pool. So a chain observer sees two unconnected sets of transfers and can link neither a user to Zetta nor a user's deposit to their payout.

**What is not private.** Inside our system we necessarily see the same link the public doesn't: which funding address credits which account. That visibility is deliberate — it is what lets us screen every deposit before crediting it, enforce monthly caps, and freeze any user instantly. What we never see is real-world identity or user keys; no balance moves without a valid signature from the user's device.

**The off-chain node.** It mirrors on-chain transfers, generates the ZK proofs that credit deposits and move value into the pool, and runs the ledger (balances, cards, withdrawals).

**Corporate status.** Zetta is currently a solo founder; no legal entity is registered yet. Incorporation will follow once the model in Section 2 is confirmed — this letter exists so we don't incorporate around a business a card platform won't permit. Pilot treasury is founder-funded; no investor or customer funds have ever moved through the system.

We are asking about card issuance and payout rails. We are not asking Laso to custody user relationships — the users are ours.

## 2. The model we are asking you to approve

The core mechanic, plainly: **cards ordered on our account are assigned to end users.** A user's balance is funded by their own deposits; on their request Zetta orders a single-load card and delivers the card details to that user in-app. Zetta itself never spends the cards.

Your published card terms state cards are "intended for the caller's own use" and "non-transferable." Read plainly, our model conflicts with that language. So — before building on Laso — we are asking for written confirmation that this partner float model (Zetta orders, end users spend) is acceptable, or a clear statement of what would make it acceptable: a separate product, per-user or per-card limits, user-facing disclosures, or an enterprise agreement. If it is not acceptable in any form, we would much rather learn that now than after users and their money are live.

**This is the only blocking question.** Everything below is context for it.

## 3. What we would use

Our primary integration is the USA prepaid card (`GET /get-card`, $5–$1,000 per card, single-load). Phase 2 adds the international card (`GET /order-intl-card`) for non-US users and push-to-card (`GET /get-push-to-card`) for fiat cash-outs. Phase 3 optionally adds gift cards (`/order-gift-card`) as an in-app shop.

Integration is self-custody: our backend holds its own Base wallet and pays each order per-request over x402 — an EIP-3009 signature for the exact amount, settled atomically. No float is parked at Laso.

## 4. Our no-KYC position

We are no-KYC by design, and we will stay no-KYC. Laso's own card product is also no-KYC, so we are not asking for anything Laso does not already do at retail. Instead of identity, our risk model is:

1. **Hard per-user caps.** Every user is capped at $5k/month across all card issuance. This is enforced in the ledger, not by policy — exceeding it is arithmetically impossible.
2. **Single-load cards only.** Maximum $1,000 per card, never reloadable through us.
3. **Deposit screening** (Section 5).
4. **Kill switch.** We can suspend any user instantly. Laso can freeze our account at any time and nothing strands — we pay per order and hold no balance at Laso, so at most an in-flight refund credit is affected; the operating float never leaves our own wallet.

## 5. Source of funds: the deposit screen

The question nobody has to ask is: if one of our users launders money, how would anyone know? Our answer is that every deposit is screened before it is credited, without collecting identity.

Deposits into Zetta are plain ERC-20 transfers. The funding address is always visible on-chain even though the owner is private. Before a deposit is credited, we screen the funding address against Chainalysis. A flagged source is never credited: the deposit is treated as burned and permanently unspendable, a mechanism that already exists in the protocol. Screening logs are retained for 2+ years and are available to Laso on request.

The result for Laso is that USDC received from us is cleaner than retail volume, where screening happens one wallet at a time. Our pool has a gate on the way in.

## 6. Usage pattern: normal consumer spend, not churn

Cards are single-load (no top-ups) but multi-use: a user receives a card loaded with a meaningful amount — typically $100–500 — and spends it across many merchants until depleted, then requests a new one. Expected cadence is roughly 2–4 cards per active user per month, each with weeks of normal transaction history behind it. Card-level spend profiles look like ordinary consumer e-commerce, not rapid issue-and-burn cycling.

## 7. Volume — honestly stated

We are pre-launch with zero users, and we will not invent a demand forecast. The pilot (first 90 days) onboards a waitlist of 50 users with a hard total cap of $50k/month of card volume enforced in the ledger — the system cannot exceed it. Before any cap raise or wider onboarding wave we will notify Laso in advance. If the launch fails, your exposure is zero: you hold nothing of ours.

## 8. Flow of funds

Zetta's treasury holds USDC on Base. A dedicated Base funding wallet is pre-funded in lumps and pays card orders per-order via x402, settling on Base. Top-ups are lumpy by design to limit key use and keep treasury exposure bounded; both legs are plain USDC transfers on Base, so a top-up is a single fast, cheap transfer with no bridge.

Nothing is parked at Laso: payment is exact and atomic per order, so our balance at Laso is zero in steady state. Cards are issued to Zetta's Laso account and assigned to users in our ledger. Reconciliation is monthly: our ledger against Laso's transaction history.

## 9. Technical readiness

Our backend is Rust on Base (alloy), and already signs EVM transactions for payouts — x402 payment is an additional EIP-3009 signature on the same stack: no new chain integration, no custodial wallet. The card pipeline exists and runs end-to-end against a stub provider today; swapping in your route is a config change.

## 10. What we ask right now

1. **Written confirmation that the Section 2 model is acceptable** — Zetta orders, our users spend — or the specific changes that would make it acceptable.
2. If it is acceptable only under a partner/enterprise agreement: what that requires, and at what minimum scale, so we can sequence incorporation and documentation accordingly.

Everything else (volume pricing, raised limits, a named ops channel) we will raise only once we have real data — none of it is needed for the pilot.

## 11. What Laso gets if this works

Prepaid volume that grows with our user base, from a partner whose deposits are pre-screened (lower compliance cost per dollar than anonymous retail), and a flagship consumer integration to point other neobanks at. Before any of that: a counterparty that told you exactly what it was going to do before doing it.

## Appendix — Expected questions

**Who are your users?**
Privacy-conscious stablecoin holders in US/EU/Asia. Sanctioned jurisdictions are excluded at app store and IP level.

**Why no KYC at all?**
For the same reason Laso's card product has none: small, capped, single-load instruments with screened funding. Identity adds cost and excludes our core users without adding safety at these limits.

**What stops 1,000 fake users from defeating the per-user cap?**
We treat identity the way Laso does: not at issuance of small, non-redeemable instruments, but structurally — per-user caps, device-bound accounts, screened funding, and a global volume cap that makes scaled abuse economically irrational.

**What happens when a user's card is used in fraud?**
Single-load cards bound the loss to one load. We cooperate on merchant disputes and ban the user.

**What if Laso needs to freeze us?**
You can, at any time; the operating float lives in our own Base wallet, not at Laso, so a freeze strands at most in-flight refund credits. We would ask for a notification-then-freeze courtesy on velocity flags so we can provide context first.

## Open questions for Laso

1. When a refund or credit is issued to a self-custody account (no managed wallet) — including an order refused after settlement (e.g. a freeze between payment and issuance, or a failed push-to-card) — does it return on-chain to the paying Base address, or land as account credit withdrawable only on Solana? On what timeline?
2. Do you offer a test environment (e.g. x402 on Base Sepolia) for integration development?
3. Beyond "US merchants only," which merchant categories are structurally declined on the USA card?
4. What rate limits apply to card-ordering endpoints per account, beyond the service-wide ceiling?
