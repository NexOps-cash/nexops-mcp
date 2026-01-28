# Knowledge Base Requirements

This document specifies the additional knowledge base content needed to enhance NexOps MCP's code generation capabilities.

## Current KB Status

✅ **Completed:**
- 18 security rules (covenant validation, output limits, minting control, etc.)
- 7 secure code patterns (covenant validation, sidecar attach, position validation, etc.)
- BCH Knowledge Base integrated (security architecture, best practices)

## Required KB Additions

### 1. Anti-Patterns (CRITICAL - Highest Priority)

**Purpose:** Teach the LLM what NOT to generate by showing vulnerable code examples.

**Location:** `knowledge/anti_patterns/`

**Required Files:**

#### `vulnerable_covenant.cash`
- Missing lockingBytecode check (code injection vulnerability)
- Missing tokenCategory check (category substitution)
- Missing value validation (value extraction)
- Example showing attacker exploit scenario

#### `missing_output_limit.cash`
- Function without `require(tx.outputs.length <= N)`
- Explanation of minting attack vector
- Example showing how attacker adds unauthorized outputs

#### `unvalidated_position.cash`
- Contract not checking `this.activeInputIndex`
- Example of input reordering attack
- Shows how attacker swaps oracle/main contract positions

#### `minting_authority_leak.cash`
- Minting NFT sent to user address
- Example of compromised token system
- Shows proper vs improper minting control

#### `time_validation_error.cash`
- Using `>` instead of `>=` for locktime
- Edge case vulnerability at exact boundary
- Correct vs incorrect time comparison

#### `missing_token_validation.cash`
- Output without tokenCategory check
- Attacker attaching tokens to BCH-only output
- Proper validation pattern

### 2. Contract Type Templates (High Priority)

**Purpose:** Provide complete, working examples of common contract types.

**Location:** `knowledge/templates/`

**Required Files:**

#### `escrow_2of3.cash`
- 2-of-3 multisig escrow with timelock refund
- Buyer, seller, arbiter roles
- Dispute resolution mechanism
- Timelock-based refund after deadline

#### `vesting_linear.cash`
- Linear token vesting over time
- Cliff period support
- Partial claim mechanism
- Revocation by issuer (optional)

#### `crowdfunding_refundable.cash`
- Goal-based crowdfunding
- Refund mechanism if goal not met
- Deadline enforcement
- Pledge tracking with NFT receipts

#### `auction_english.cash`
- English auction (ascending price)
- Bid validation and outbid refund
- Auction end time enforcement
- Winner claim mechanism

#### `auction_dutch.cash`
- Dutch auction (descending price)
- Time-based price decay
- First-come-first-served claim
- Reserve price enforcement

### 3. Common Mistake Patterns (Medium Priority)

**Purpose:** Document frequently occurring errors and their fixes.

**Location:** `knowledge/mistakes/`

**Required Files:**

#### `division_by_zero.cash`
- Missing zero check before division
- Safe division pattern
- Example: `require(denominator != 0)`

#### `integer_overflow.cash`
- Counter overflow (hitting max int)
- Safe increment pattern
- Example: `require(newID != 2147483647)`

#### `array_bounds.cash`
- Missing length validation
- Out-of-bounds access prevention
- Example: `require(index < array.length)`

#### `state_corruption.cash`
- Invalid state transition
- State length mismatch
- Proper state validation pattern

### 4. Multi-Contract Patterns (Medium Priority)

**Purpose:** Show how contracts interact in complex systems.

**Location:** `knowledge/multi_contract/`

**Required Files:**

#### `main_sidecar_pair.cash`
- Main contract holding NFT state
- Sidecar holding fungible tokens
- Same-origin verification
- Sequential index proof

#### `function_routing.cash`
- Main coordinator contract
- Multiple function contracts (0x00, 0x01, 0x02...)
- NFT commitment-based routing
- Position validation for each function

#### `oracle_consumer.cash`
- Contract consuming oracle data
- Price feed validation
- Timestamp freshness check
- Multiple oracle aggregation

## File Format Specifications

### Anti-Pattern Files
```cashscript
// ANTI-PATTERN: [Name]
// VULNERABILITY: [Description]
// ATTACK VECTOR: [How attacker exploits this]

// VULNERABLE CODE:
contract VulnerableExample() {
    function badFunction() {
        // Missing critical validation
        // ... vulnerable code
    }
}

// SECURE VERSION:
contract SecureExample() {
    function goodFunction() {
        // Proper validation
        // ... secure code
    }
}

// EXPLANATION:
// [Detailed explanation of the vulnerability and fix]
```

### Template Files
```cashscript
pragma cashscript ^0.12.1;

// CONTRACT TYPE: [Name]
// USE CASE: [Description]
// SECURITY LEVEL: [Critical/High/Medium]

contract TemplateName(
    // Constructor parameters with comments
    pubkey param1,  // Description
    int param2      // Description
) {
    // Complete, working implementation
    // With inline comments explaining logic
    // Following all security best practices
}
```

### Mistake Pattern Files
```cashscript
// COMMON MISTAKE: [Name]
// FREQUENCY: [How often this occurs]
// SEVERITY: [Critical/High/Medium/Low]

// WRONG:
function vulnerable() {
    // Mistake example
}

// CORRECT:
function secure() {
    // Fixed version
}

// WHY THIS MATTERS:
// [Explanation of consequences]
```

## Integration Notes

All files will be automatically loaded by `KnowledgeRetriever`:
- Anti-patterns will be used to filter/reject LLM output
- Templates will be injected as examples for similar contract types
- Mistake patterns will be used for validation checks

## Priority Order

1. **Anti-Patterns** (Start here - most critical for security)
2. **Contract Templates** (High value for code generation)
3. **Mistake Patterns** (Helps catch edge cases)
4. **Multi-Contract Patterns** (Advanced use cases)

## Delivery Format

Please provide files in the following structure:
```
knowledge/
├── anti_patterns/
│   ├── vulnerable_covenant.cash
│   ├── missing_output_limit.cash
│   ├── unvalidated_position.cash
│   ├── minting_authority_leak.cash
│   ├── time_validation_error.cash
│   └── missing_token_validation.cash
├── templates/
│   ├── escrow_2of3.cash
│   ├── vesting_linear.cash
│   ├── crowdfunding_refundable.cash
│   ├── auction_english.cash
│   └── auction_dutch.cash
├── mistakes/
│   ├── division_by_zero.cash
│   ├── integer_overflow.cash
│   ├── array_bounds.cash
│   └── state_corruption.cash
└── multi_contract/
    ├── main_sidecar_pair.cash
    ├── function_routing.cash
    └── oracle_consumer.cash
```

Each file should be complete, compilable CashScript code with extensive comments.
