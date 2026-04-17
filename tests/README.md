# End-to-End Tests

Integration tests exercising the full DKLs23 threshold ECDSA lifecycle: distributed key generation, signing, key refresh, and node recovery.

## Running

```bash
# Run all e2e tests (slow — OT setup takes minutes in debug mode)
cargo test --test e2e_dkg_sign_refresh --test e2e_3of5_operational_scenario -- --nocapture

# Run a single test
cargo test --test e2e_3of5_operational_scenario -- --nocapture

# Release mode is significantly faster (~5x)
cargo test --release --test e2e_3of5_operational_scenario -- --nocapture
```

`--nocapture` shows `println!` progress during execution. Without it, output is only shown on failure.

---

## `e2e_dkg_sign_refresh.rs`

**Test:** `test_e2e_fixed_3of5_dkg_p2wsh_sign_refresh`

Covers the standard protocol lifecycle for a 3-of-5 threshold setup:

1. **DKG** — All 5 parties run the 4-phase distributed key generation protocol.
2. **BIP-32 derivation** — All parties independently derive a child key at path `m/0/7`; the derived public key is verified to be identical across all parties.
3. **P2WSH address** — A Bitcoin mainnet P2WSH address is computed from the derived group public key and validated.
4. **Signing** — Parties 1, 2, 3 execute the 4-phase signing protocol; the resulting ECDSA signature is verified against the group public key.
5. **Complete refresh** — All 5 parties re-randomize their key shares while preserving the public key.
6. **Post-refresh signing** — Signing is repeated with the refreshed parties to confirm correctness.

---

## `e2e_3of5_operational_scenario.rs`

**Test:** `test_3of5_operational_backup_failover`

Simulates a realistic operational deployment where N=3 parties are kept online for signing and M-N=2 parties are kept offline as backups. Exercises node loss, failover, and two different recovery strategies.

### Scenario flow

| Step | Description |
|------|-------------|
| 1 | **DKG** with all 5 parties — generates the shared key. |
| 2 | **Sign with [1, 2, 3]** — only the operational nodes. |
| 3 | **Sign with [1, 4, 5]** — mixed group proves any 3-of-5 works. |
| 4 | **Complete refresh** — all 5 parties participate, shares are re-randomized, public key unchanged. |
| 5 | **Sign with [1, 2, 3]** — post-refresh, operational nodes still work. |
| 6 | **Party 2 lost** — sign with [1, 3, 4] to prove threshold resilience. |
| 7 | **Refresh (scenario a)** — party 2 recovered from backup, participates in refresh, then goes offline again. |
| 8 | **Sign with [1, 3, 4]** — new operational set works after refresh. |
| 9 | **All 3-of-5 combos** — verifies [2,3,5], [1,4,5], [3,4,5], [1,2,5] all produce valid signatures. |
| 10 | **Reshare via `re_key` (scenario b)** — party 2 permanently lost; survivors [1,3,4] reconstruct the secret via Lagrange interpolation at x=0 and create a fresh 5-party set. Sign + refresh + sign to verify. |
| 11 | **Hollow party replacement (scenario b-distributed)** — party 2 permanently lost; survivors reconstruct *only* the missing share f(2) via Lagrange at x=2, build a hollow party (correct share, empty OT state), and run a complete refresh that rebuilds all cryptographic state from scratch. Sign with the revived party to verify. |

### Key concepts demonstrated

- **Threshold signing**: only `t` out of `n` parties are needed to sign; the remaining parties can be offline.
- **Refresh**: re-randomizes all shares without changing the public key. Requires all `n` parties.
- **Failover**: when an operational node is lost, any backup can replace it for signing (no protocol change needed).
- **Reshare via `re_key`**: when a party is permanently lost, `threshold` survivors can reconstruct the secret and re-deal to a new party set. Requires momentary reconstruction of the secret key — suitable for secure enclaves.
- **Hollow party replacement**: a safer alternative where only the missing party's share (not the secret) is reconstructed. The hollow party participates in a complete refresh to obtain valid OT/zero-share state.

### Debug output

Each phase prints progress and, at key milestones, displays:
- The group **public key** (compressed SEC1, constant across all operations)
- The **private key** (reconstructed from threshold shares via Lagrange — for test/debug only)
- Each party's individual **key share** (`poly_point` — changes on every refresh)
