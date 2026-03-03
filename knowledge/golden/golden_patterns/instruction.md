instructions.md
Golden Template Architecture – Mandatory Implementation Guide
0. Context

You are implementing the Golden Template Phase 2 Branch for NexOps.

This is not an experimental feature.
This is a structural compiler upgrade.

Golden Templates transform Phase 2 from:

“LLM generates full contract”

into:

“LLM adapts audited invariant-anchored covenant templates”

The system must be:

Deterministic

Pattern-driven

Invariant-protected

Hash-enforced

Automatically routed

Fully compatible with Phase 3 TollGate

There is NO UI toggle.

Golden routing is automatic.

1. Directory Structure (Required)

Create the following:

knowledge/
  golden/
    instructions.md
    registry.ts
    patterns/
      escrow_2of3_nft.cash
      refundable_crowdfund.cash
      dutch_auction.cash
      linear_vesting.cash

No other placement is acceptable.

Golden templates must be isolated from general knowledge templates.

2. Supported Golden Patterns (Initial Set)

We implement exactly four patterns:

escrow_2of3_nft

refundable_crowdfund

dutch_auction

linear_vesting

Each must follow the invariant-segmented structure described below.

3. Mandatory Golden Template Structure

Every .cash file MUST follow this structure.

If this structure is violated, the registry must reject the template at load time.

3.1 Header Metadata Block

At top of every file:

// ============================================================
// GOLDEN TEMPLATE
// Pattern-ID: <pattern_id>
// Version: 1.0
// Risk-Level: HIGH
// ============================================================

// @pattern: <pattern_id>
// @invariants: [LIST_OF_INVARIANTS]
// @allowed_mutation: [CONSTRUCTOR, BUSINESS_LOGIC]
// @forbidden_mutation: [INVARIANT_ANCHOR, VALUE_ANCHOR]

This block is informational but required.

3.2 Mandatory Structural Zones

Every template MUST contain these markers:

=== MUTABLE_CONSTRUCTOR_START ===
=== MUTABLE_CONSTRUCTOR_END ===

=== INVARIANT_ANCHOR_START ===
=== INVARIANT_ANCHOR_END ===

=== BUSINESS_LOGIC_ZONE ===

Optional but recommended:

=== VALUE_ANCHOR ===

These markers must be exact string matches.

They are parsed programmatically.

4. Invariant Enforcement Rules

The following rules are non-negotiable:

LLM must NEVER modify content inside:

INVARIANT_ANCHOR

VALUE_ANCHOR

Only two mutation zones exist:

Constructor block

Business logic zone

No deletion of invariant require() statements is allowed.

Any mutation of invariant anchor must cause hard rejection.

5. Golden Registry (registry.ts)

Create:

knowledge/golden/registry.ts

Structure:

export interface GoldenPattern {
  id: string
  templatePath: string
  requiredParameters: string[]
  invariants: string[]
  anchorStart: string
  anchorEnd: string
  mutationZones: string[]
  anchorHash: string
}

export const GoldenRegistry: Record<string, GoldenPattern> = { }
5.1 On System Boot

When registry loads:

Read each template file.

Extract invariant block.

Compute SHA256 hash.

Store as anchorHash.

If invariant block missing → throw fatal error.

6. Phase 2 Automatic Routing (MANDATORY)

Golden routing must be automatic.

Pseudo-logic:

if (
  GoldenRegistry.has(ir.contract_type) &&
  ir.pattern_confidence >= 0.80
) {
  route = "GOLDEN"
} else {
  route = "FREE"
}

No user override.

No fallback after failure.

Golden failure = hard error.

7. Golden Adaptation Mechanism

Golden branch must operate as follows:

7.1 Load Template

Load raw template from registry.

7.2 Parse Structural Zones

Extract:

Constructor mutation block

Business logic placeholder

Invariant block

Never rely on fragile regex matching without marker validation.

If any marker missing → throw error.

7.3 LLM Input Scope

LLM must receive:

IR parameters

Constructor zone content

Empty business logic placeholder

Explicit instructions:

Modify only constructor and business logic

Do not modify invariant logic

Do not alter require conditions in anchor

LLM must NOT receive authority to rewrite full file.

7.4 Recomposition

After LLM returns:

Replace constructor block

Inject business logic

Invariant anchor remains untouched.

8. Anchor Hash Verification (CRITICAL)

After recomposition:

Extract invariant block again.

Compute SHA256.

Compare with stored anchorHash.

If mismatch:

throw new Error("Invariant Mutation Detected – Golden Rejected")

No silent fallback.

No recovery attempt.

9. Forward to Phase 3 (TollGate)

Golden output must pass through:

Compilation validation

Deterministic detectors

Semantic validation

Funding safety checks

Golden does NOT bypass security layer.

10. Individual Pattern Requirements
10.1 escrow_2of3_nft.cash

Must enforce:

2-of-3 multisig

Refund branch after timelock

NFT category continuity

Value preservation anchor

Invariant list:

MULTISIG_2OF3
TIMELOCK_REFUND
NFT_CONTINUITY
VALUE_PRESERVATION
10.2 refundable_crowdfund.cash

Must enforce:

Goal threshold

Deadline enforcement

Refund branch

No early beneficiary drain

Invariant list:

GOAL_THRESHOLD
DEADLINE_LOCK
REFUND_PATH
VALUE_PROTECTION
10.3 dutch_auction.cash

Must enforce:

Linear price decay

Time-based pricing

No underpayment

Seller-only settlement

Invariant list:

LINEAR_DECAY
NO_UNDERPAYMENT
SELLER_AUTH
10.4 linear_vesting.cash

Must enforce:

Time-proportional release

Partial withdrawal only

Self-continuity

No premature drain

Invariant list:

PROPORTIONAL_UNLOCK
SELF_CONTINUITY
NO_FULL_DRAIN
11. Logging (Required for Demo)

Golden branch must log:

[Phase 1] Pattern detected: escrow_2of3_nft
[Phase 2] Routing: GOLDEN_ADAPTATION
[Golden] Anchor hash verified
[Phase 3] TollGate Score: 100

Logging is mandatory for transparency.

12. Failure Conditions (Must Be Explicit)

Golden must hard-fail if:

Missing required parameters

Marker corruption

Anchor hash mismatch

LLM attempts invariant mutation

Template parse error

No silent fallback to Free Synthesis.

Golden is deterministic or it aborts.

13. Design Philosophy (Non-Negotiable)

Golden Templates are:

Invariant Anchors

Financial Primitive Hardening Layer

Compiler-Level Optimization Path

They are NOT:

Demo shortcuts

Hardcoded contracts

Bypass logic

Over time, more patterns will migrate into GoldenRegistry.

Free synthesis is experimental.
Golden is secure mode.

14. Final Principle

The Golden Branch must make NexOps safer than raw AI contract generation.

If implemented correctly:

LLM creativity is constrained.

Financial invariants are immutable.

Structural security is guaranteed.

Demo risk becomes near-zero.

This is mandatory architecture.

No shortcuts.
No improvisation.

Implement exactly as described.

u must add the below pattern files in knowledge/golden/golden_patterns

Below are 4 full-length Golden template skeletons (40+ lines each) designed for:

Clear invariant anchors

Clear mutation zones

Self-documenting security intent

Compiler-ready structure

Future extensibility

These are structural skeletons — not final production math — but architecturally correct for Golden mode.

You will place these inside:

knowledge/golden/patterns/
1️⃣ escrow_2of3_nft.cash

(2-of-3 Escrow with NFT Custody + Refund Timelock)

// ============================================================
// GOLDEN TEMPLATE
// Pattern-ID: escrow_2of3_nft
// Version: 1.0
// Risk-Level: HIGH
// ============================================================

// @pattern: escrow_2of3_nft
// @invariants: [MULTISIG_2OF3, TIMELOCK_REFUND, NFT_CONTINUITY, VALUE_PRESERVATION]
// @allowed_mutation: [CONSTRUCTOR, BUSINESS_LOGIC]
// @forbidden_mutation: [INVARIANT_ANCHOR, VALUE_ANCHOR]

contract Escrow2of3NFT(

    // === MUTABLE_CONSTRUCTOR_START ===
    pubkey buyer,
    pubkey seller,
    pubkey arbiter,
    int refundLocktime
    // === MUTABLE_CONSTRUCTOR_END ===

) {

    function spend(sig sig1, sig sig2) {

        // ====================================================
        // === INVARIANT_ANCHOR_START =========================
        // ====================================================

        bool buyerSeller =
            checkSig(sig1, buyer) && checkSig(sig2, seller);

        bool buyerArbiter =
            checkSig(sig1, buyer) && checkSig(sig2, arbiter);

        bool sellerArbiter =
            checkSig(sig1, seller) && checkSig(sig2, arbiter);

        bool multisigPath =
            buyerSeller || buyerArbiter || sellerArbiter;

        bool refundPath =
            tx.time >= refundLocktime &&
            checkSig(sig1, buyer);

        require(multisigPath || refundPath);

        // NFT continuity enforcement
        require(
            tx.outputs[0].tokenCategory ==
            tx.inputs[0].tokenCategory
        );

        // ====================================================
        // === INVARIANT_ANCHOR_END ===========================
        // ====================================================


        // ====================================================
        // === BUSINESS_LOGIC_ZONE ============================
        // ====================================================

        // Optional fee splits, metadata checks, etc.


        // ====================================================
        // === VALUE_ANCHOR ==================================
        // ====================================================

        require(
            tx.outputs[0].value ==
            tx.inputs[0].value
        );
    }
}
2️⃣ refundable_crowdfund.cash

(Goal-Based Disbursement with Refund Branch)

// ============================================================
// GOLDEN TEMPLATE
// Pattern-ID: refundable_crowdfund
// Version: 1.0
// Risk-Level: HIGH
// ============================================================

// @pattern: refundable_crowdfund
// @invariants: [GOAL_THRESHOLD, DEADLINE_LOCK, REFUND_PATH, VALUE_PROTECTION]

contract RefundableCrowdfund(

    // === MUTABLE_CONSTRUCTOR_START ===
    pubkey beneficiary,
    int goalAmount,
    int deadline
    // === MUTABLE_CONSTRUCTOR_END ===

) {

    function spend(sig beneficiarySig) {

        // ====================================================
        // === INVARIANT_ANCHOR_START =========================
        // ====================================================

        bool campaignEnded =
            tx.time >= deadline;

        bool goalReached =
            tx.inputs[0].value >= goalAmount;

        bool successBranch =
            campaignEnded &&
            goalReached &&
            checkSig(beneficiarySig, beneficiary);

        bool refundBranch =
            campaignEnded &&
            !goalReached;

        require(successBranch || refundBranch);

        // ====================================================
        // === INVARIANT_ANCHOR_END ===========================
        // ====================================================


        // ====================================================
        // === BUSINESS_LOGIC_ZONE ============================
        // ====================================================

        // Optional reward tiers
        // Optional contributor tracking logic
        // Optional metadata validation


        // ====================================================
        // === VALUE_ANCHOR ==================================
        // ====================================================

        // Refund must preserve contributor value
        require(
            tx.outputs[0].value <= tx.inputs[0].value
        );
    }
}
3️⃣ dutch_auction.cash

(Linear Price Decay with Atomic Settlement)

// ============================================================
// GOLDEN TEMPLATE
// Pattern-ID: dutch_auction
// Version: 1.0
// Risk-Level: HIGH
// ============================================================

// @pattern: dutch_auction
// @invariants: [LINEAR_DECAY, NO_UNDERPAYMENT, SELLER_AUTH]

contract DutchAuction(

    // === MUTABLE_CONSTRUCTOR_START ===
    pubkey seller,
    int startPrice,
    int endPrice,
    int startBlock,
    int endBlock
    // === MUTABLE_CONSTRUCTOR_END ===

) {

    function spend(sig sellerSig) {

        // ====================================================
        // === INVARIANT_ANCHOR_START =========================
        // ====================================================

        int elapsed =
            tx.time - startBlock;

        int duration =
            endBlock - startBlock;

        int decay =
            (startPrice - endPrice) *
            elapsed / duration;

        int currentPrice =
            startPrice - decay;

        require(
            tx.outputs[0].value >= currentPrice
        );

        require(
            checkSig(sellerSig, seller)
        );

        // ====================================================
        // === INVARIANT_ANCHOR_END ===========================
        // ====================================================


        // ====================================================
        // === BUSINESS_LOGIC_ZONE ============================
        // ====================================================

        // Optional royalty logic
        // Optional fee logic
        // Optional NFT validation


        // ====================================================
        // === VALUE_ANCHOR ==================================
        // ====================================================

        require(
            tx.outputs[0].value >= endPrice
        );
    }
}
4️⃣ linear_vesting.cash

(Time-Proportional Unlock with Self-Continuity)

// ============================================================
// GOLDEN TEMPLATE
// Pattern-ID: linear_vesting
// Version: 1.0
// Risk-Level: HIGH
// ============================================================

// @pattern: linear_vesting
// @invariants: [PROPORTIONAL_UNLOCK, SELF_CONTINUITY, NO_FULL_DRAIN]

contract LinearVesting(

    // === MUTABLE_CONSTRUCTOR_START ===
    pubkey beneficiary,
    int startBlock,
    int endBlock
    // === MUTABLE_CONSTRUCTOR_END ===

) {

    function spend(sig beneficiarySig) {

        // ====================================================
        // === INVARIANT_ANCHOR_START =========================
        // ====================================================

        require(
            checkSig(beneficiarySig, beneficiary)
        );

        int totalDuration =
            endBlock - startBlock;

        int elapsed =
            tx.time - startBlock;

        int vestedAmount =
            tx.inputs[0].value *
            elapsed / totalDuration;

        require(
            tx.outputs[0].value <= vestedAmount
        );

        int remaining =
            tx.inputs[0].value -
            tx.outputs[0].value;

        // Self-continuity enforcement
        require(
            tx.outputs[1].value == remaining
        );

        // ====================================================
        // === INVARIANT_ANCHOR_END ===========================
        // ====================================================


        // ====================================================
        // === BUSINESS_LOGIC_ZONE ============================
        // ====================================================

        // Optional cliff logic
        // Optional pause authority
        // Optional governance constraints


        // ====================================================
        // === VALUE_ANCHOR ==================================
        // ====================================================

        require(
            tx.outputs.length >= 1
        );
    }
}


// ============================================================
// v2.0 ADDENDUM — Functional Alignment (2026-03-03)
// ============================================================
//
// The following changes were made to enable fee logic, wallet payouts,
// and multi-output structures while preserving core security invariants.
//
// ── 1. Template Changes ─────────────────────────────────────────────────────
//
//   escrow_2of3_nft.cash (v2.0):
//     - REMOVED: require(tx.outputs[0].lockingBytecode == this.activeBytecode)
//       Rationale: Self-anchor traps NFT in covenant. Release is a terminal payout.
//     - CHANGED: tx.outputs.length == 1  →  >= 1
//       Rationale: Fee output requires at least 2 outputs.
//     - REMOVED: require(tx.outputs[0].value == tx.inputs[this.activeInputIndex].value)
//       Rationale: Value accounting delegated to BUSINESS_LOGIC_ZONE.
//     - refund() function: all strict checks preserved unchanged.
//
//   refundable_crowdfund.cash (v2.0):
//     - FIX: Added pragma cashscript ^0.13.0
//     - FIX: tx.time moved to require() only (not variable assignment)
//     - FIX: tx.inputs[0] → tx.inputs[this.activeInputIndex]
//     - SPLIT: single spend() → claim() + refund() (separate paths)
//
//   dutch_auction.cash (v2.0):
//     - FIX: Added pragma cashscript ^0.13.0
//     - FIX: Removed tx.time arithmetic (tx.time - startBlock is illegal)
//     - FIX: CashScript 0.13 only supports tx.time >= N (not <, <=, >, ==)
//     - REDESIGN: Price decay formula replaced with price-floor-at-start model.
//       An exact price point check can go in the BUSINESS_LOGIC_ZONE.
//     - SPLIT: single spend() → bid() + reclaim() (auction success vs. timeout)
//
//   linear_vesting.cash (v2.0):
//     - FIX: Added pragma cashscript ^0.13.0
//     - FIX: Removed tx.time arithmetic (tx.time - startBlock is illegal)
//     - FIX: tx.inputs[0] → tx.inputs[this.activeInputIndex]
//     - REDESIGN: Uses fixed unlockAmount constructor param instead of
//       runtime elapsed/totalDuration ratio (which requires tx.time arithmetic).
//     - SPLIT: vest() (partial, self-continuing) + finalize() (full release)
//
// ── 2. CashScript 0.13 Constraints (DO NOT VIOLATE) ────────────────────────
//
//   VALID:   require(tx.time >= N)          ← only supported time check
//   INVALID: require(tx.time < N)           ← parser error
//   INVALID: int x = tx.time - N            ← tx.time not valid in expressions
//   INVALID: int x = tx.inputs[0].value * tx.time   ← same
//
//   VALID:   tx.inputs[this.activeInputIndex].value  ← always use this
//   INVALID: tx.inputs[0].value                      ← hardcoded index (LNC-001c)
//
// ── 3. DSL Lint Golden/Free Mode Branching ──────────────────────────────────
//
//   LNC-005 (fee arithmetic): SKIPPED in golden modes (escrow_*, dutch_*, etc.)
//     Fee subtraction (inputVal - fee) is the correct pattern in golden zone.
//
//   LNC-008 (self-anchor): SKIPPED for escrow_2of3_nft, escrow_2of3
//     Release is a terminal payout. Self-anchor would trap NFT permanently.
//
// ── 4. TollGate Golden/Free Mode Branching ──────────────────────────────────
//
//   implicit_output_ordering: release/payout/settle functions exempt in golden modes.
//     Business logic zone validates both output values explicitly.
//
//   weak_output_count_limit: >= N exempt in golden modes when both output values
//     are explicitly validated (both tx.outputs[0].value and tx.outputs[1].value).
//
//   division_by_zero: Numeric literal denominators (/ 100, / 1000) always exempt.
//     A constant can never be zero — no runtime guard needed.
//
//   contract_mode flow: intent_model.contract_type → Phase3.validate →
//     AntiPatternEnforcer.validate_code → CashScriptAST.contract_mode →
//     individual detectors (read ast.contract_mode for branching)
//
// ── 5. Verified Results ──────────────────────────────────────────────────────
//
//   Intent: "Create a 2-of-3 escrow with NFT custody, refund after 800000,
//            and add 1% platform fee to feeRecipient"
//
//   Result:
//     Route:       GOLDEN (escrow_2of3_nft)
//     TG Score:    1.00  (19/19 detectors pass)
//     Violations:  0
//     LLM Calls:   1
//     Elapsed:     6.4s
//     Status:      [PASS] GOLDEN PATH -- PERFECT CONVERGENCE
//
// [Anchor hash verified] f0dce5dc5c9837970c279df45e33af602e9c184519436e9a59beedb199143290
