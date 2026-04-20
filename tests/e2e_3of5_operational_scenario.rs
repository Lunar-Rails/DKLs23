//! E2E test: 3-of-5 operational scenario
//!
//! Scenario:
//! - 5 parties participate in DKG (all M=5 required for key generation)
//! - Only N=3 parties are "operational" (parties 1,2,3) and used for signing
//! - Parties 4,5 are "backup" — they hold shares but don't sign
//! - After signing, all 5 parties do a complete refresh
//! - Then party 2 is "lost" and replaced by party 4 (a backup)
//! - The new signing group (1,3,4) signs successfully
//! - A second refresh is run with the new operational set + remaining backup

use std::collections::BTreeMap;

use dkls23::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4,
};
use dkls23::protocols::dkg_session::DkgSession;
use dkls23::protocols::sign_session::SignSession;
use dkls23::protocols::signing::{
    verify_ecdsa_signature, Broadcast3to4, SignData, TransmitPhase1to2, TransmitPhase2to3,
};
use dkls23::protocols::derivation::DerivData;
use dkls23::protocols::dkg::compute_eth_address;
use dkls23::protocols::re_key::re_key;
use dkls23::protocols::{Parameters, Party, PartyIndex};
use dkls23::utilities::hashes::tagged_hash;
use dkls23::utilities::rng;
use dkls23::utilities::zero_shares::ZeroShare;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::elliptic_curve::Field;
use k256::Scalar;

const THRESHOLD: u8 = 3;
const SHARE_COUNT: u8 = 5;
const SESSION_ID: [u8; 32] = [0xA0; 32];

/// Print the public key (compressed SEC1) and, for debug, reconstruct and show the
/// private key from the first `threshold` shares via Lagrange interpolation at x=0.
/// Also shows each party's individual key share (poly_point).
fn print_key_state(label: &str, parties: &[Party]) {
    let pk_bytes = parties[0].pk.to_sec1_point(true);
    let pk_hex = hex::encode(pk_bytes.as_bytes());
    println!("  [keys] {label}");
    println!("         pub key (compressed): {pk_hex}");

    // Reconstruct private key from threshold shares (ONLY for test/debug)
    let shares: Vec<(u8, Scalar)> = parties
        .iter()
        .take(THRESHOLD as usize)
        .map(|p| (p.party_index.as_u8(), p.poly_point))
        .collect();
    let secret = lagrange_interpolate_at(&shares, 0);
    let secret_hex = hex::encode(secret.to_bytes());
    println!("         priv key (reconstructed from parties {:?}): {secret_hex}",
        shares.iter().map(|(i, _)| *i).collect::<Vec<_>>());

    // Show individual shares
    for p in parties {
        let share_hex = hex::encode(p.poly_point.to_bytes());
        println!("         party {} share: {share_hex}", p.party_index.as_u8());
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run full 4-phase DKG for a 3-of-5 setup, returning all 5 parties.
fn run_dkg() -> Vec<Party> {
    let params = Parameters {
        threshold: THRESHOLD,
        share_count: SHARE_COUNT,
    };
    let n = SHARE_COUNT as usize;

    let mut sessions: Vec<DkgSession> = (1..=SHARE_COUNT)
        .map(|i| DkgSession::new(params.clone(), PartyIndex::new(i).unwrap(), SESSION_ID.to_vec()))
        .collect();

    // Phase 1
    println!("  [dkg] phase 1: generating random polynomials...");
    let phase1: Vec<Vec<Scalar>> = sessions.iter().map(DkgSession::phase1).collect();
    println!("  [dkg] phase 1 done");

    let mut poly_frags = vec![Vec::<Scalar>::with_capacity(n); n];
    for row in phase1 {
        for (j, val) in row.into_iter().enumerate() {
            poly_frags[j].push(val);
        }
    }

    // Phase 2
    println!("  [dkg] phase 2: sharing polynomial evaluations + proofs...");
    let mut proofs = Vec::with_capacity(n);
    let mut zero_tx_2 = Vec::with_capacity(n);
    let mut bip_bc_2: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> = BTreeMap::new();

    for (i, session) in sessions.iter_mut().enumerate() {
        let (proof, zt, bb) = session.phase2(&poly_frags[i]).expect("dkg p2");
        proofs.push(proof);
        zero_tx_2.push(zt);
        bip_bc_2.insert(PartyIndex::new(i as u8 + 1).unwrap(), bb);
    }

    let zero_rx_2 = route_messages_by_receiver(&zero_tx_2, |m| m.parties.receiver);
    println!("  [dkg] phase 2 done — routing zero-share messages");

    // Phase 3
    println!("  [dkg] phase 3: initializing zero-shares + OT multiplications...");
    let mut zero_tx_3 = Vec::with_capacity(n);
    let mut mul_tx_3 = Vec::with_capacity(n);
    let mut bip_bc_3: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> = BTreeMap::new();

    for (i, session) in sessions.iter_mut().enumerate() {
        let (zt, mt, bb) = session.phase3().expect("dkg p3");
        zero_tx_3.push(zt);
        mul_tx_3.push(mt);
        bip_bc_3.insert(PartyIndex::new(i as u8 + 1).unwrap(), bb);
    }

    let zero_rx_3 = route_messages_by_receiver(&zero_tx_3, |m| m.parties.receiver);
    let mul_rx_3 = route_messages_by_receiver(&mul_tx_3, |m| m.parties.receiver);
    println!("  [dkg] phase 3 done — routing messages");

    // Phase 4
    println!("  [dkg] phase 4: validating proofs + assembling parties...");
    let mut parties = Vec::with_capacity(n);
    for (i, session) in sessions.into_iter().enumerate() {
        let (party, _pkg) = session
            .phase4(
                &proofs,
                &zero_rx_2[i],
                &zero_rx_3[i],
                &mul_rx_3[i],
                &bip_bc_2,
                &bip_bc_3,
            )
            .expect("dkg p4");
        parties.push(party);
    }
    println!("  [dkg] phase 4 done — {} parties created", parties.len());
    parties
}

/// Sign a message using an arbitrary subset of parties (must be >= threshold).
fn sign_with(parties: &[Party], signer_indices: &[u8], sign_id: [u8; 32], msg_hash: [u8; 32]) {
    println!("  [sign] phase 1: creating sign sessions for parties {:?}...", signer_indices);
    let mut sessions: BTreeMap<u8, SignSession> = BTreeMap::new();
    let mut tx_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();

    for &idx in signer_indices {
        let counterparties: Vec<PartyIndex> = signer_indices
            .iter()
            .copied()
            .filter(|&i| i != idx)
            .map(|i| PartyIndex::new(i).unwrap())
            .collect();

        let data = SignData {
            sign_id: sign_id.to_vec(),
            counterparties,
            message_hash: msg_hash,
        };

        let party = parties
            .iter()
            .find(|p| p.party_index == PartyIndex::new(idx).unwrap())
            .expect("party exists");

        let (session, transmit) = SignSession::new(party, data).expect("sign p1");
        sessions.insert(idx, session);
        tx_1to2.insert(idx, transmit);
    }

    // Route phase 1→2
    let mut rx_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
    for &idx in signer_indices {
        let pi = PartyIndex::new(idx).unwrap();
        let msgs: Vec<TransmitPhase1to2> = tx_1to2
            .values()
            .flatten()
            .filter(|m| m.parties.receiver == pi)
            .cloned()
            .collect();
        rx_1to2.insert(idx, msgs);
    }

    // Phase 2
    println!("  [sign] phase 2: computing partial signatures...");
    let mut tx_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
    for &idx in signer_indices {
        let tx = sessions
            .get_mut(&idx)
            .unwrap()
            .phase2(rx_1to2.get(&idx).unwrap())
            .expect("sign p2");
        tx_2to3.insert(idx, tx);
    }

    // Route phase 2→3
    let mut rx_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
    for &idx in signer_indices {
        let pi = PartyIndex::new(idx).unwrap();
        let msgs: Vec<TransmitPhase2to3> = tx_2to3
            .values()
            .flatten()
            .filter(|m| m.parties.receiver == pi)
            .cloned()
            .collect();
        rx_2to3.insert(idx, msgs);
    }

    // Phase 3
    println!("  [sign] phase 3: generating broadcasts...");
    let mut broadcasts: Vec<Broadcast3to4> = Vec::with_capacity(signer_indices.len());
    for &idx in signer_indices {
        let bc = sessions
            .get_mut(&idx)
            .unwrap()
            .phase3(rx_2to3.get(&idx).unwrap())
            .expect("sign p3");
        broadcasts.push(bc);
    }

    // Phase 4 — leader assembles signature
    println!("  [sign] phase 4: leader assembling final signature...");
    let leader = signer_indices[0];
    let sig = sessions
        .remove(&leader)
        .unwrap()
        .phase4(&broadcasts, true)
        .expect("sign p4");

    assert_ne!(sig.r, [0u8; 32]);
    assert_ne!(sig.s, [0u8; 32]);

    let r_hex = hex::encode(sig.r);
    let s_hex = hex::encode(sig.s);
    assert!(
        verify_ecdsa_signature(&msg_hash, &parties[0].pk, &r_hex, &s_hex),
        "signature verification failed"
    );
    println!(
        "  ✓ signature valid (signers: {:?}, r: {}…)",
        signer_indices,
        &r_hex[..16]
    );
}

/// Complete refresh across ALL parties (all 5 must participate).
fn refresh_all(parties: &[Party], refresh_sid: &[u8; 32]) -> Vec<Party> {
    let n = parties.len();

    // Phase 1
    println!("  [refresh] phase 1: generating refresh polynomials...");
    let phase1: Vec<Vec<Scalar>> = parties.iter().map(|p| p.refresh_complete_phase1()).collect();

    let mut poly_frags = vec![Vec::<Scalar>::with_capacity(n); n];
    for row in phase1 {
        for (j, val) in row.into_iter().enumerate() {
            poly_frags[j].push(val);
        }
    }

    // Phase 2
    println!("  [refresh] phase 2: computing correction values + proofs...");
    let mut corrections = Vec::with_capacity(n);
    let mut proofs = Vec::with_capacity(n);
    let mut zero_kept_2 = Vec::with_capacity(n);
    let mut zero_tx_2 = Vec::with_capacity(n);

    for (i, party) in parties.iter().enumerate() {
        let (cv, proof, zk, zt) = party.refresh_complete_phase2(refresh_sid, &poly_frags[i]);
        corrections.push(cv);
        proofs.push(proof);
        zero_kept_2.push(zk);
        zero_tx_2.push(zt);
    }

    let zero_rx_2 = route_messages_by_receiver(&zero_tx_2, |m| m.parties.receiver);
    println!("  [refresh] phase 2 done");

    // Phase 3
    println!("  [refresh] phase 3: re-initializing zero-shares + OT multiplications...");
    let mut zero_kept_3 = Vec::with_capacity(n);
    let mut zero_tx_3 = Vec::with_capacity(n);
    let mut mul_kept_3 = Vec::with_capacity(n);
    let mut mul_tx_3 = Vec::with_capacity(n);

    for (i, party) in parties.iter().enumerate() {
        let (zk, zt, mk, mt) = party.refresh_complete_phase3(refresh_sid, &zero_kept_2[i]);
        zero_kept_3.push(zk);
        zero_tx_3.push(zt);
        mul_kept_3.push(mk);
        mul_tx_3.push(mt);
    }

    let zero_rx_3 = route_messages_by_receiver(&zero_tx_3, |m| m.parties.receiver);
    let mul_rx_3 = route_messages_by_receiver(&mul_tx_3, |m| m.parties.receiver);
    println!("  [refresh] phase 3 done");

    // Phase 4
    println!("  [refresh] phase 4: validating + assembling refreshed parties...");
    let mut refreshed = Vec::with_capacity(n);
    for (i, party) in parties.iter().enumerate() {
        let r = party
            .refresh_complete_phase4(
                refresh_sid,
                &corrections[i],
                &proofs,
                &zero_kept_3[i],
                &zero_rx_2[i],
                &zero_rx_3[i],
                &mul_kept_3[i],
                &mul_rx_3[i],
            )
            .expect("refresh p4");
        refreshed.push(r);
    }
    println!("  [refresh] phase 4 done — {} parties refreshed", refreshed.len());
    refreshed
}

/// Generic message routing: given a Vec<Vec<M>>, collect messages destined to
/// each party index (1..=SHARE_COUNT) into separate Vecs.
fn route_messages_by_receiver<M: Clone>(
    all_messages: &[Vec<M>],
    get_receiver: impl Fn(&M) -> PartyIndex,
) -> Vec<Vec<M>> {
    (1..=SHARE_COUNT)
        .map(|i| {
            let pi = PartyIndex::new(i).unwrap();
            all_messages
                .iter()
                .flatten()
                .filter(|m| get_receiver(m) == pi)
                .cloned()
                .collect()
        })
        .collect()
}

/// Lagrange interpolation: evaluate the polynomial defined by `shares` at `target_x`.
/// Each share is (party_index, poly_point). For x=0 this reconstructs the secret key.
fn lagrange_interpolate_at(shares: &[(u8, Scalar)], target_x: u8) -> Scalar {
    let x_target = Scalar::from(u32::from(target_x));
    let mut result = Scalar::ZERO;
    for (i, &(xi, yi)) in shares.iter().enumerate() {
        let mut lagrange = Scalar::ONE;
        for (j, &(xj, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj_scalar = Scalar::from(u32::from(xj));
            let xi_scalar = Scalar::from(u32::from(xi));
            let num = x_target - xj_scalar;
            let den = xi_scalar - xj_scalar;
            let den_inv: Scalar = Option::from(den.invert()).expect("non-zero denominator");
            lagrange *= num * den_inv;
        }
        result += yi * lagrange;
    }
    result
}

/// Reconstruct the secret key (interpolate at x=0).
fn reconstruct_secret(shares: &[(u8, Scalar)]) -> Scalar {
    lagrange_interpolate_at(shares, 0)
}

/// MPC-style Lagrange interpolation using pairwise additive masks.
///
/// Simulates the distributed protocol where each surviving party holds ONLY
/// its own share and never learns the others' shares. The flow is:
///
/// 1. Each party `i` computes its term locally: `tᵢ = yᵢ · Lᵢ(target)`.
///    The Lagrange coefficient `Lᵢ(target)` uses only PUBLIC information
///    (the x-coordinates of the surviving parties and the target index),
///    so no secret leaves the node at this step.
///
/// 2. Each pair of surviving parties `(i, j)` with `i < j` agrees on a
///    random scalar `r_{ij}` (in a real deployment, via a pairwise secure
///    channel — e.g. ECDH). Party `i` adds `+r_{ij}` to its term; party
///    `j` adds `-r_{ij}`. The sum across all parties cancels every mask.
///
/// 3. Each party broadcasts its masked term to the recipient only. From a
///    single masked value, nobody (not even the recipient) can recover the
///    underlying share — the random mask acts as a one-time pad.
///
/// 4. The recipient sums the masked terms. The pairwise masks cancel out,
///    leaving exactly `Σᵢ tᵢ = f(target)`. Only the recipient learns this
///    value; the other participants never see the sum.
///
/// This is the same "pairwise zero-share" trick used internally by DKLs23
/// for its zero_shares module during signing.
fn lagrange_mpc_at_target(shares: &[(u8, Scalar)], target_x: u8) -> Scalar {
    let x_target = Scalar::from(u32::from(target_x));
    let n = shares.len();

    // --- Step 1: each party computes its own term locally (uses only its
    //     own yᵢ and the public x-coordinates of all participants) -------
    let local_terms: Vec<Scalar> = (0..n)
        .map(|i| {
            let (xi, yi) = shares[i];
            let xi_scalar = Scalar::from(u32::from(xi));
            let mut lagrange = Scalar::ONE;
            for j in 0..n {
                if i == j {
                    continue;
                }
                let xj_scalar = Scalar::from(u32::from(shares[j].0));
                let num = x_target - xj_scalar;
                let den = xi_scalar - xj_scalar;
                let den_inv: Scalar = Option::from(den.invert()).expect("non-zero denominator");
                lagrange *= num * den_inv;
            }
            yi * lagrange
        })
        .collect();

    // --- Step 2: pairwise random masks r_{ij} for i < j ------------------
    // pair_mask[i][j] holds the signed mask party i adds for its pairing
    // with party j: +r for i<j, -r for i>j. Sum over all parties cancels.
    let mut pair_mask: Vec<Vec<Scalar>> = vec![vec![Scalar::ZERO; n]; n];
    for i in 0..n {
        for j in (i + 1)..n {
            let r = Scalar::random(&mut rng::get_rng());
            pair_mask[i][j] = r;
            pair_mask[j][i] = -r;
        }
    }

    // --- Step 3: each party broadcasts its masked term to the recipient --
    let masked_terms: Vec<Scalar> = (0..n)
        .map(|i| {
            let mut masked = local_terms[i];
            for j in 0..n {
                if i == j {
                    continue;
                }
                masked += pair_mask[i][j];
            }
            masked
        })
        .collect();

    // --- Step 4: recipient sums the masked terms; masks cancel pairwise --
    masked_terms
        .iter()
        .fold(Scalar::ZERO, |acc, t| acc + t)
}

/// Build a "hollow" Party — correct poly_point but empty OT/zero-share state.
/// This party is NOT capable of signing, but CAN participate in a complete
/// refresh (which rebuilds all cryptographic state from scratch).
fn build_hollow_party(
    template: &Party,
    new_index: u8,
    poly_point: Scalar,
) -> Party {
    Party {
        parameters: template.parameters.clone(),
        party_index: PartyIndex::new(new_index).unwrap(),
        session_id: template.session_id.clone(),
        poly_point,
        pk: template.pk,
        zero_share: ZeroShare::initialize(vec![]),
        mul_senders: BTreeMap::new(),
        mul_receivers: BTreeMap::new(),
        derivation_data: DerivData {
            depth: template.derivation_data.depth,
            child_number: template.derivation_data.child_number,
            parent_fingerprint: template.derivation_data.parent_fingerprint,
            poly_point,
            pk: template.pk,
            chain_code: template.derivation_data.chain_code,
        },
        eth_address: compute_eth_address(&template.pk),
    }
}

/// Reshare: given `threshold` surviving parties, reconstruct the secret and
/// use `re_key` to create a brand-new party set with the same public key.
/// The new set can have different parameters (threshold, share_count).
fn reshare_from_survivors(
    survivors: &[&Party],
    new_params: &Parameters,
    new_session_id: &[u8],
) -> Vec<Party> {
    // Collect (party_index, poly_point) pairs from survivors
    let shares: Vec<(u8, Scalar)> = survivors
        .iter()
        .map(|p| (p.party_index.as_u8(), p.poly_point))
        .collect();

    println!(
        "  [reshare] reconstructing secret from {} shares (parties {:?})...",
        shares.len(),
        shares.iter().map(|(i, _)| *i).collect::<Vec<_>>()
    );
    let secret = reconstruct_secret(&shares);

    // Preserve the chain code from the original parties
    let chain_code = survivors[0].derivation_data.chain_code;

    println!(
        "  [reshare] re-keying into new {}-of-{} party set...",
        new_params.threshold, new_params.share_count
    );
    let (new_parties, _pkg) = re_key(new_params, new_session_id, &secret, Some(chain_code));

    // Verify the public key is preserved
    let original_pk = survivors[0].pk;
    assert_eq!(
        new_parties[0].pk, original_pk,
        "reshare must preserve the public key"
    );
    for p in &new_parties {
        assert_eq!(p.pk, original_pk);
    }

    println!(
        "  ✓ reshare complete — {} new parties, same pk",
        new_parties.len()
    );
    new_parties
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[test]
fn test_3of5_operational_backup_failover() {
    // -----------------------------------------------------------------------
    // 1. DKG: all 5 parties generate the shared key
    // -----------------------------------------------------------------------
    println!("[scenario] DKG with all 5 parties");
    let parties = run_dkg();

    let pk = parties[0].pk;
    let chain_code = parties[0].derivation_data.chain_code;
    for p in &parties {
        assert_eq!(p.pk, pk, "all parties must share the same public key");
        assert_eq!(p.derivation_data.chain_code, chain_code);
    }
    println!("  ✓ DKG complete — all 5 parties hold shares, same pk");
    print_key_state("after DKG", &parties);

    // -----------------------------------------------------------------------
    // 2. Sign with only the N=3 operational parties (1, 2, 3)
    // -----------------------------------------------------------------------
    println!("[scenario] Sign with operational parties [1, 2, 3]");
    let msg1 = tagged_hash(b"scenario-sign-1", &[b"first signing"]);
    sign_with(&parties, &[1, 2, 3], [0xB1; 32], msg1);

    // -----------------------------------------------------------------------
    // 3. Verify that backup parties (4, 5) can also form a valid signing group
    //    with any operational party (just to prove threshold works)
    // -----------------------------------------------------------------------
    println!("[scenario] Sign with mixed group [1, 4, 5] (1 operational + 2 backup)");
    let msg2 = tagged_hash(b"scenario-sign-2", &[b"mixed signing"]);
    sign_with(&parties, &[1, 4, 5], [0xB2; 32], msg2);

    // -----------------------------------------------------------------------
    // 4. Complete refresh — all 5 parties participate
    //    (backup parties 4,5 MUST participate to get new shares)
    // -----------------------------------------------------------------------
    println!("[scenario] Complete refresh with all 5 parties");
    let refreshed = refresh_all(&parties, &[0xC1; 32]);

    for p in &refreshed {
        assert_eq!(p.pk, pk, "refresh must preserve the public key");
    }
    println!("  ✓ refresh complete — pk unchanged, all shares re-randomized");
    print_key_state("after 1st refresh", &refreshed);

    // -----------------------------------------------------------------------
    // 5. Sign after refresh with operational parties [1, 2, 3]
    // -----------------------------------------------------------------------
    println!("[scenario] Post-refresh sign with [1, 2, 3]");
    let msg3 = tagged_hash(b"scenario-sign-3", &[b"post-refresh signing"]);
    sign_with(&refreshed, &[1, 2, 3], [0xB3; 32], msg3);

    // -----------------------------------------------------------------------
    // 6. Simulate loss of party 2 — replace with backup party 4
    //    New operational set: [1, 3, 4]
    // -----------------------------------------------------------------------
    println!("[scenario] Party 2 LOST — signing with [1, 3, 4]");
    let msg4 = tagged_hash(b"scenario-sign-4", &[b"failover signing"]);
    sign_with(&refreshed, &[1, 3, 4], [0xB4; 32], msg4);

    // -----------------------------------------------------------------------
    // 7. Refresh after failover — party 2 is gone, but the protocol requires
    //    ALL share_count parties. In a real system you would either:
    //    (a) still have party 2's share (just offline) and bring it back, or
    //    (b) do a reshare with a new party set.
    //
    //    Here we simulate (a): party 2 is "recovered from backup" and
    //    participates in refresh, then goes back offline.
    // -----------------------------------------------------------------------
    println!("[scenario] Refresh with all 5 (party 2 recovered from backup for refresh)");
    let refreshed2 = refresh_all(&refreshed, &[0xC2; 32]);

    for p in &refreshed2 {
        assert_eq!(p.pk, pk, "second refresh must preserve the public key");
    }
    println!("  ✓ second refresh complete");
    print_key_state("after 2nd refresh", &refreshed2);

    // -----------------------------------------------------------------------
    // 8. Sign with the new operational set [1, 3, 4] after second refresh
    // -----------------------------------------------------------------------
    println!("[scenario] Post-second-refresh sign with new operational set [1, 3, 4]");
    let msg5 = tagged_hash(b"scenario-sign-5", &[b"new operational signing"]);
    sign_with(&refreshed2, &[1, 3, 4], [0xB5; 32], msg5);

    // -----------------------------------------------------------------------
    // 9. Bonus: verify any 3-of-5 combo works after all refreshes
    // -----------------------------------------------------------------------
    println!("[scenario] Verify arbitrary 3-of-5 combos work");
    let combos: &[&[u8]] = &[
        &[2, 3, 5],
        &[1, 4, 5],
        &[3, 4, 5],
        &[1, 2, 5],
    ];
    for (i, combo) in combos.iter().enumerate() {
        let mut sid = [0xD0; 32];
        sid[0] = i as u8;
        let msg = tagged_hash(b"scenario-combo", &[&[i as u8]]);
        sign_with(&refreshed2, combo, sid, msg);
    }

    // -----------------------------------------------------------------------
    // 10. SCENARIO (b): Party 2 is PERMANENTLY gone — reshare to new party set
    //     Using only threshold survivors (1, 3, 4), reconstruct the secret
    //     and re-key into a fresh 3-of-5 set. This is a "nuclear option" that
    //     requires momentary reconstruction of the secret (in production, this
    //     would happen inside a secure enclave or via an MPC protocol).
    // -----------------------------------------------------------------------
    println!("\n[scenario] === RESHARE: party 2 permanently lost ===");
    println!("[scenario] Reconstructing from survivors [1, 3, 4] and creating new 3-of-5 set");

    let survivors: Vec<&Party> = [1u8, 3, 4]
        .iter()
        .map(|&i| {
            refreshed2
                .iter()
                .find(|p| p.party_index == PartyIndex::new(i).unwrap())
                .unwrap()
        })
        .collect();

    let new_params = Parameters {
        threshold: THRESHOLD,
        share_count: SHARE_COUNT,
    };
    let reshared_parties = reshare_from_survivors(&survivors, &new_params, &[0xE0; 32]);

    // Verify pk matches the original
    assert_eq!(reshared_parties[0].pk, pk, "reshared pk must match original");
    print_key_state("after reshare (re_key)", &reshared_parties);

    // Sign with the new party set — all indices are now 1..=5 (fresh set)
    println!("[scenario] Sign with reshared parties [1, 2, 3]");
    let msg6 = tagged_hash(b"scenario-sign-6", &[b"reshared signing"]);
    sign_with(&reshared_parties, &[1, 2, 3], [0xB6; 32], msg6);

    println!("[scenario] Sign with reshared parties [3, 4, 5]");
    let msg7 = tagged_hash(b"scenario-sign-7", &[b"reshared signing alt"]);
    sign_with(&reshared_parties, &[3, 4, 5], [0xB7; 32], msg7);

    // Refresh the reshared set (all 5 new parties participate)
    println!("[scenario] Refresh reshared parties");
    let reshared_refreshed = refresh_all(&reshared_parties, &[0xC3; 32]);
    assert_eq!(reshared_refreshed[0].pk, pk, "refresh after reshare must preserve pk");
    println!("  ✓ reshared + refreshed — pk still matches original");
    print_key_state("after reshare + refresh", &reshared_refreshed);

    // Final sign after reshare + refresh
    println!("[scenario] Final sign after reshare + refresh with [2, 4, 5]");
    let msg8 = tagged_hash(b"scenario-sign-8", &[b"final signing"]);
    sign_with(&reshared_refreshed, &[2, 4, 5], [0xB8; 32], msg8);

    // -----------------------------------------------------------------------
    // 11. SCENARIO (b-distributed): Party 2 is PERMANENTLY gone — but instead
    //     of reconstructing the full secret, the survivors reconstruct ONLY
    //     the missing share f(2) via Lagrange interpolation at x=2, build a
    //     "hollow" Party 2 (correct poly_point, empty OT state), and run a
    //     complete refresh to bring it to life.
    //
    //     This is safer than scenario 10 because the secret key f(0) is NEVER
    //     reconstructed — only the individual share f(2) is computed.
    //     Additionally, the interpolation itself runs as a simulated MPC:
    //     each survivor computes its own Lagrange term with pairwise-random
    //     masks that cancel in the final sum, so no single node (other than
    //     party 2, the recipient) ever learns f(2).
    // -----------------------------------------------------------------------
    println!("\n[scenario] === HOLLOW PARTY REPLACEMENT via complete refresh ===");

    // Use the same refreshed2 state. Party 2 is "gone" — we only have 1,3,4,5.
    let survivor_shares: Vec<(u8, Scalar)> = [1u8, 3, 4]
        .iter()
        .map(|&i| {
            let p = refreshed2
                .iter()
                .find(|p| p.party_index == PartyIndex::new(i).unwrap())
                .unwrap();
            (i, p.poly_point)
        })
        .collect();

    // Reconstruct ONLY the missing share at x=2 (NOT the secret at x=0),
    // and do it via simulated MPC: each survivor computes its own Lagrange
    // term locally, masks it with pairwise randomness that cancels in the
    // sum, and only the recipient (party 2) learns the final value.
    println!(
        "  [hollow] running MPC interpolation at x=2 across survivors {:?}...",
        survivor_shares.iter().map(|(i, _)| *i).collect::<Vec<_>>()
    );
    let reconstructed_share_2 = lagrange_mpc_at_target(&survivor_shares, 2);

    // Sanity check: the MPC protocol must produce the same scalar as the
    // direct (centralized) interpolation. The difference is only in WHO
    // gets to see intermediate values during the computation.
    let direct_share_2 = lagrange_interpolate_at(&survivor_shares, 2);
    assert_eq!(
        reconstructed_share_2, direct_share_2,
        "MPC interpolation must agree with the direct computation"
    );
    println!("  [hollow] MPC result matches direct interpolation ✓");
    println!("  [hollow] reconstructed poly_point for party 2 (only party 2 sees this value)");

    // Build a hollow Party 2 — correct share, but no OT/zero-share state
    let template = &refreshed2[0]; // any surviving party as template for metadata
    let hollow_party_2 = build_hollow_party(template, 2, reconstructed_share_2);

    // Assemble the full 5-party set: real parties [1,3,4,5] + hollow party 2
    let mut parties_with_hollow: Vec<Party> = refreshed2
        .iter()
        .filter(|p| p.party_index != PartyIndex::new(2).unwrap())
        .cloned()
        .collect();
    parties_with_hollow.push(hollow_party_2);
    parties_with_hollow.sort_by_key(|p| p.party_index);

    // Complete refresh — this rebuilds ALL OT/zero-share state from scratch,
    // making the hollow party 2 fully functional
    println!("[scenario] Complete refresh with hollow party 2 in the set");
    let revived = refresh_all(&parties_with_hollow, &[0xC4; 32]);

    for p in &revived {
        assert_eq!(p.pk, pk, "refresh with hollow party must preserve pk");
    }
    println!("  ✓ hollow party 2 is now fully operational after refresh");
    print_key_state("after hollow replacement + refresh", &revived);

    // Sign with party 2 included — proves it's now a fully functional member
    println!("[scenario] Sign with revived party 2: [1, 2, 3]");
    let msg9 = tagged_hash(b"scenario-sign-9", &[b"revived party signing"]);
    sign_with(&revived, &[1, 2, 3], [0xB9; 32], msg9);

    println!("[scenario] Sign with revived party 2: [2, 4, 5]");
    let msg10 = tagged_hash(b"scenario-sign-10", &[b"revived party alt"]);
    sign_with(&revived, &[2, 4, 5], [0xBA; 32], msg10);

    // Verify all 3-of-5 combos still work
    println!("[scenario] Verify all combos after hollow replacement");
    let post_combos: &[&[u8]] = &[&[1, 2, 4], &[2, 3, 5], &[1, 3, 5]];
    for (i, combo) in post_combos.iter().enumerate() {
        let mut sid = [0xF0; 32];
        sid[0] = i as u8;
        let msg = tagged_hash(b"scenario-hollow-combo", &[&[i as u8]]);
        sign_with(&revived, combo, sid, msg);
    }

    println!("\n[scenario] ALL CHECKS PASSED ✓");
}
