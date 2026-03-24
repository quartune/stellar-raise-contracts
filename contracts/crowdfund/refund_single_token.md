# refund_single() Token Transfer Logic

## Purpose

This update introduces a dedicated `refund_single` pathway to make refund scripts simpler and less error-prone while keeping transfer behavior explicit and auditable.

## What changed

- Added `refund_single(env, contributor)` to `contracts/crowdfund/src/lib.rs`
- Added shared helper module `contracts/crowdfund/src/refund_single_token.rs`
- Added focused tests in `contracts/crowdfund/src/refund_single_token.test.rs`

## Contract behavior

`refund_single` allows a contributor to refund their own contribution after campaign failure.

### Preconditions

- campaign status must be `Active`
- current timestamp must be after `deadline`
- campaign goal must not be reached
- `contributor.require_auth()` must pass

### Effects

- transfers `amount` from contract to contributor
- clears contributor contribution storage value
- decreases `TotalRaised` by refunded amount
- emits `("campaign", "refund_single")` event

If the contributor has `0` stored contribution, the function returns `Ok(())` without transfer.

## Security assumptions and validations

1. **Transfer direction hardening**  
   Refund transfer uses a shared helper with explicit parameter names:
   `refund_single_transfer(token_client, contract_address, contributor, amount)`.
   This reduces script-side confusion and prevents accidental reverse transfer direction in call sites.

2. **Authorization boundary**  
   `refund_single` requires contributor auth, so only the contributor can trigger their single-address refund flow.

3. **State invariants**  
   Function enforces same campaign state checks as batch `refund`:
   - no refunds before deadline
   - no refunds when goal is met

4. **Accounting consistency**  
   `TotalRaised` is reduced with checked subtraction to avoid silent underflow-style bugs.

## Test coverage

`refund_single_token.test.rs` covers:

- successful transfer + contribution reset + total update
- single-target behavior when multiple contributors exist
- `CampaignStillActive` error before deadline
- `GoalReached` error when campaign already met funding target

## Notes for reviewers

- Existing `refund` now reuses `refund_single_transfer` helper for consistency.
- Change is intentionally minimal and isolated to refund transfer logic for easy diff review.
