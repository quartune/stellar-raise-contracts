# stellar_token_minter — Crowdfund Contract Security Module

Technical reference for the Stellar Raise crowdfund smart contract security module built with Soroban SDK.

---

## Overview

The `stellar_token_minter` module provides secure token minting and pledge collection functionality for the Stellar Raise crowdfunding platform. This module contains validation functions and security checks that are used internally by the crowdfund contract.

---

## Module Functions

### Validation Functions

#### `validate_pledge_preconditions`

```rust
pub fn validate_pledge_preconditions(
    env: &Env,
    amount: i128,
    min_contribution: i128,
) -> Result<(), ContractError>
```

Validates preconditions for pledge operations.

**Security Checks:**
1. Campaign must be active (`CampaignNotActive` if not)
2. Amount must be non-zero (`ZeroAmount` if zero)
3. Amount must meet minimum (`BelowMinimum` if below)
4. Current time must be before deadline (`CampaignEnded` if past)

**Validation Order:** Status → Amount → Deadline (prevents timing-based attacks)

#### `validate_collect_preconditions`

```rust
pub fn validate_collect_preconditions(
    env: &Env,
) -> Result<(i128, i128, i128), ContractError>
```

Validates preconditions for collect_pledges operations.

**Returns:** `(goal, total_raised, total_pledged)` on success

**Security Checks:**
1. Campaign must be active (`CampaignNotActive` if not)
2. Current time must be after deadline (`CampaignStillActive` if before)
3. Combined total must meet goal (`GoalNotReached` if below)
4. No overflow in total calculation (`Overflow` if overflow)

### Arithmetic Helper Functions

#### `calculate_total_commitment`

```rust
pub fn calculate_total_commitment(
    total_raised: i128,
    total_pledged: i128,
) -> Result<i128, ContractError>
```

Safely calculates the total commitment (raised + pledged).

- Uses `checked_add` to prevent overflow
- Returns `ContractError::Overflow` if addition would overflow

#### `safe_add_pledge`

```rust
pub fn safe_add_pledge(
    current_total: i128,
    new_amount: i128,
) -> Result<i128, ContractError>
```

Validates that a pledge amount can be safely added to existing totals.

#### `validate_contribution_amount`

```rust
pub fn validate_contribution_amount(
    amount: i128,
    min_contribution: i128,
) -> Result<(), ContractError>
```

Validates contribution amounts for security.

- Non-zero amount prevents dust transactions
- Amount >= minimum prevents spam

#### `safe_calculate_progress`

```rust
pub fn safe_calculate_progress(
    current_amount: i128,
    goal: i128,
) -> Result<u32, ContractError>
```

Safely calculates campaign progress in basis points (BPS).

- Returns progress from 0 to 10,000 (where 10,000 = 100%)
- Caps at 100% to prevent display issues
- Uses checked arithmetic for overflow protection

### Parameter Validation Functions

#### `validate_deadline`

```rust
pub fn validate_deadline(
    env: &Env,
    deadline: u64,
) -> Result<(), ContractError>
```

Validates that a deadline is in the future.

- Returns `CampaignEnded` if deadline is in the past or current
- Checks against maximum campaign duration (1 year)

#### `validate_goal`

```rust
pub fn validate_goal(goal: i128) -> Result<(), ContractError>
```

Validates that a goal amount is reasonable.

- Returns `GoalNotReached` for zero or negative goals

#### `calculate_platform_fee`

```rust
pub fn calculate_platform_fee(
    amount: i128,
    fee_bps: u32,
) -> Result<i128, ContractError>
```

Calculates platform fee safely with bounds checking.

- Fee BPS should be 0-10000
- Uses checked arithmetic

#### `validate_bonus_goal`

```rust
pub fn validate_bonus_goal(
    bonus_goal: i128,
    primary_goal: i128,
) -> Result<(), ContractError>
```

Validates bonus goal is strictly greater than primary goal.

- Returns `GoalNotReached` if bonus ≤ primary

---

## Security Features

### Authorization Enforcement

All state-changing operations require proper authentication via Soroban's `require_auth` mechanism.

### Overflow Protection

All arithmetic operations use `checked_*` methods:
- `checked_add` for additions
- `checked_mul` for multiplications
- `checked_div` for divisions

This prevents integer overflow attacks on financial calculations.

### State Validation

Strict validation of campaign state before operations:
1. Status check occurs first
2. Input validation follows
3. Timing checks last

This order ensures consistent error reporting and prevents state confusion attacks.

### Deadline Enforcement

Time-based guards use strict inequality comparisons:
- `timestamp > deadline` for pledge operations (deadline is exclusive)
- `timestamp <= deadline` for collection operations (must wait until after)

### Goal Verification

Ensures pledges are only collected when goals are met:
- Combined totals are atomically validated
- Overflow protection on total calculations
- Strict comparison against goal

---

## Attack Vectors Mitigated

| Attack Vector | Mitigation |
|---|---|
| Integer Overflow | All arithmetic uses `checked_*` operations |
| Deadline Bypass | Timestamp comparisons use strict inequality |
| State Confusion | Status checks occur before any modifications |
| Goal Manipulation | Combined totals atomically validated |
| Dust Attacks | Zero and minimum amount validation |
| Reentrancy | Soroban execution model is single-threaded |
| TOCTOU | Atomic reads of all values before comparison |

---

## Error Codes

| Code | Variant | Meaning |
|---|---|---|
| 1 | `AlreadyInitialized` | Initialize called more than once |
| 2 | `CampaignEnded` | Action attempted after deadline |
| 3 | `CampaignStillActive` | Action requires deadline to have passed |
| 4 | `GoalNotReached` | Withdraw/collect attempted when goal not met |
| 5 | `GoalReached` | Refund attempted when goal was met |
| 6 | `Overflow` | Integer overflow in calculations |
| 7 | `NothingToRefund` | Caller has no contribution to refund |
| 8 | `ZeroAmount` | Amount is zero |
| 9 | `BelowMinimum` | Amount is below minimum contribution |
| 10 | `CampaignNotActive` | Campaign is not in active state |

---

## Testing

Tests are located in `contracts/crowdfund/src/stellar_token_minter.test.rs`.

### Test Categories

1. **Authorization Tests**: Verify authentication requirements
2. **Overflow Protection Tests**: Ensure arithmetic safety
3. **State Transition Tests**: Validate state machine integrity
4. **Timing Tests**: Verify deadline enforcement
5. **Goal Validation Tests**: Ensure goal requirements
6. **Edge Case Tests**: Cover boundary conditions
7. **Module Function Tests**: Unit tests for module functions
8. **Integration Tests**: End-to-end workflow tests

### Running Tests

```bash
# Run all stellar_token_minter tests
cargo test --package crowdfund stellar_token_minter

# Run with detailed output
cargo test --package crowdfund stellar_token_minter -- --nocapture

# Run specific test
cargo test --package crowdfund test_pledge_requires_authorization
```

### Test Coverage

| Function | Tests |
|---|---|
| `calculate_total_commitment` | Success, zero values, overflow detection, boundary values |
| `safe_add_pledge` | Success, overflow, zero addition, multiple accumulations |
| `validate_contribution_amount` | Valid, exact minimum, zero, below minimum |
| `safe_calculate_progress` | Zero goal, exact, halfway, overfunded, small amounts |
| `validate_deadline` | Future, past, exact current |
| `validate_goal` | Positive, zero, negative |
| `calculate_platform_fee` | Zero BPS, 1%, 5%, 100% |
| `validate_bonus_goal` | Valid, equal to primary, less than primary |
| `validate_pledge_preconditions` | Success, zero, below minimum, after deadline, inactive |
| `validate_collect_preconditions` | Before deadline, at deadline, goal not met, success, inactive |

---

## Integration

The module is designed to be used internally by the crowdfund contract:

```rust
use crate::stellar_token_minter;

fn pledge(env: Env, pledger: Address, amount: i128) -> Result<(), ContractError> {
    // Use module validation functions
    stellar_token_minter::validate_pledge_preconditions(
        &env,
        amount,
        min_contribution
    )?;
    
    // ... rest of pledge logic
}
```

---

## Security Invariants

The module guarantees:

1. **No Integer Overflow**: All financial calculations are overflow-safe
2. **Strict Validation Order**: Status → Inputs → Timing
3. **Atomic Reads**: All values read at once to prevent TOCTOU
4. **Consistent Error Codes**: Same errors for same failure conditions
5. **Non-zero Amounts**: Zero transactions are rejected
6. **Minimum Enforcement**: Amounts below minimum are rejected
7. **Deadline Strictness**: Deadline comparisons are always exclusive

---

## Changelog

### v2.0.0

- Added comprehensive NatSpec documentation
- Added `safe_calculate_progress` function
- Added `validate_deadline` function
- Added `validate_goal` function
- Added `calculate_platform_fee` function
- Added `validate_bonus_goal` function
- Added extensive unit tests in module
- Improved test documentation

### v1.0.0

- Initial module structure
- Core validation functions
- Basic overflow protection
