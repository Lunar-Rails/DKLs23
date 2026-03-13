use std::collections::BTreeMap;

use bech32::{u5, ToBase32, Variant};
use bitcoin_hashes::sha256;
use dkls23::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23::protocols::dkg_session::DkgSession;
use dkls23::protocols::sign_session::SignSession;
use dkls23::protocols::signing::{verify_ecdsa_signature, Broadcast3to4, SignData, TransmitPhase1to2, TransmitPhase2to3};
use dkls23::protocols::{Parameters, Party, PartyIndex};
use dkls23::utilities::hashes::tagged_hash;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{AffinePoint, Scalar};

const THRESHOLD: u8 = 3;
const SHARE_COUNT: u8 = 5;
const SESSION_ID: [u8; 32] = [0x11; 32];
const SIGN_ID_PRE_REFRESH: [u8; 32] = [0x22; 32];
const SIGN_ID_POST_REFRESH: [u8; 32] = [0x24; 32];
const REFRESH_SID: [u8; 32] = [0x33; 32];
const CHILD_DERIVATION_PATH: &str = "m/0/7";

fn p2wsh_mainnet_from_group_key(pk: &AffinePoint) -> String {
    let enc = pk.to_sec1_point(true);
    let pubkey = enc.as_bytes();

    let mut script = Vec::with_capacity(35);
    script.push(0x21); // push 33 bytes
    script.extend_from_slice(pubkey);
    script.push(0xAC); // OP_CHECKSIG

    let witness_program = sha256::Hash::hash(&script).to_byte_array();

    let mut data = Vec::with_capacity(1 + witness_program.len());
    data.push(u5::try_from_u8(0).expect("valid segwit v0 version"));
    data.extend_from_slice(&witness_program.to_base32());

    bech32::encode("bc", data, Variant::Bech32).expect("valid bech32 encoding")
}

fn run_fixed_3of5_dkg() -> Vec<Party> {
    let parameters = Parameters {
        threshold: THRESHOLD,
        share_count: SHARE_COUNT,
    };

    let mut sessions: Vec<DkgSession> = (1..=SHARE_COUNT)
        .map(|i| DkgSession::new(parameters.clone(), PartyIndex::new(i).unwrap(), SESSION_ID.to_vec()))
        .collect();

    let n = SHARE_COUNT as usize;

    println!("[e2e][dkg] phase1 start");
    let dkg_phase1: Vec<Vec<Scalar>> = sessions.iter().map(DkgSession::phase1).collect();
    println!("[e2e][dkg] phase1 done");

    let mut poly_fragments = vec![Vec::<Scalar>::with_capacity(n); n];
    for row in dkg_phase1 {
        for j in 0..SHARE_COUNT {
            poly_fragments[j as usize].push(row[j as usize]);
        }
    }

    let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(n);
    let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    let mut bip_broadcast_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> =
        BTreeMap::new();

    println!("[e2e][dkg] phase2 start");
    for (i, session) in sessions.iter_mut().enumerate() {
        let (proof_commitment, zero_transmit, bip_broadcast) =
            session.phase2(&poly_fragments[i]).expect("dkg phase2 should succeed");
        proofs_commitments.push(proof_commitment);
        zero_transmit_2to4.push(zero_transmit);
        bip_broadcast_2to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
    }
    println!("[e2e][dkg] phase2 done");

    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for i in 1..=SHARE_COUNT {
        let pi = PartyIndex::new(i).unwrap();
        let mut row = Vec::with_capacity(n - 1);
        for party_messages in &zero_transmit_2to4 {
            for message in party_messages {
                if message.parties.receiver == pi {
                    row.push(message.clone());
                }
            }
        }
        zero_received_2to4.push(row);
    }

    let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(n);
    let mut bip_broadcast_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> =
        BTreeMap::new();

    println!("[e2e][dkg] phase3 start");
    for (i, session) in sessions.iter_mut().enumerate() {
        let (zero_transmit, mul_transmit, bip_broadcast) =
            session.phase3().expect("dkg phase3 should succeed");
        zero_transmit_3to4.push(zero_transmit);
        mul_transmit_3to4.push(mul_transmit);
        bip_broadcast_3to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
    }
    println!("[e2e][dkg] phase3 done");

    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(n);
    for i in 1..=SHARE_COUNT {
        let pi = PartyIndex::new(i).unwrap();

        let mut zero_row = Vec::with_capacity(n - 1);
        for party_messages in &zero_transmit_3to4 {
            for message in party_messages {
                if message.parties.receiver == pi {
                    zero_row.push(message.clone());
                }
            }
        }
        zero_received_3to4.push(zero_row);

        let mut mul_row = Vec::with_capacity(n - 1);
        for party_messages in &mul_transmit_3to4 {
            for message in party_messages {
                if message.parties.receiver == pi {
                    mul_row.push(message.clone());
                }
            }
        }
        mul_received_3to4.push(mul_row);
    }

    let mut parties: Vec<Party> = Vec::with_capacity(n);
    println!("[e2e][dkg] phase4 start");
    for (i, session) in sessions.into_iter().enumerate() {
        let (party, _pkg) = session
            .phase4(
                &proofs_commitments,
                &zero_received_2to4[i],
                &zero_received_3to4[i],
                &mul_received_3to4[i],
                &bip_broadcast_2to4,
                &bip_broadcast_3to4,
            )
            .expect("dkg phase4 should succeed");
        parties.push(party);
    }
    println!("[e2e][dkg] phase4 done");

    parties
}

fn run_sign_with_parties(parties: &[Party], sign_id: [u8; 32], msg_hash: [u8; 32]) {
    let signers: Vec<u8> = vec![1, 2, 3];

    let mut sessions: BTreeMap<u8, SignSession> = BTreeMap::new();
    let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();

    for party_index in signers.clone() {
        let counterparties: Vec<PartyIndex> = signers
            .iter()
            .copied()
            .filter(|i| *i != party_index)
            .map(|i| PartyIndex::new(i).unwrap())
            .collect();

        let data = SignData {
            sign_id: sign_id.to_vec(),
            counterparties,
            message_hash: msg_hash,
        };

        let (session, transmit) = SignSession::new(&parties[(party_index - 1) as usize], data)
            .expect("sign session phase1 should succeed");
        sessions.insert(party_index, session);
        transmit_1to2.insert(party_index, transmit);
    }

    let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
    for party_index in signers.clone() {
        let pi = PartyIndex::new(party_index).unwrap();
        let messages: Vec<TransmitPhase1to2> = transmit_1to2
            .values()
            .flatten()
            .filter(|message| message.parties.receiver == pi)
            .cloned()
            .collect();
        received_1to2.insert(party_index, messages);
    }

    let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
    for party_index in signers.clone() {
        let transmit = sessions
            .get_mut(&party_index)
            .expect("session exists")
            .phase2(received_1to2.get(&party_index).expect("received messages exist"))
            .expect("sign session phase2 should succeed");
        transmit_2to3.insert(party_index, transmit);
    }

    let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3>> = BTreeMap::new();
    for party_index in signers.clone() {
        let pi = PartyIndex::new(party_index).unwrap();
        let messages: Vec<TransmitPhase2to3> = transmit_2to3
            .values()
            .flatten()
            .filter(|message| message.parties.receiver == pi)
            .cloned()
            .collect();
        received_2to3.insert(party_index, messages);
    }

    let mut broadcasts: Vec<Broadcast3to4> = Vec::with_capacity(THRESHOLD as usize);
    for party_index in signers.clone() {
        let broadcast = sessions
            .get_mut(&party_index)
            .expect("session exists")
            .phase3(received_2to3.get(&party_index).expect("received messages exist"))
            .expect("sign session phase3 should succeed");
        broadcasts.push(broadcast);
    }

    let leader = signers[0];
    let signature = sessions
        .remove(&leader)
        .expect("leader session exists")
        .phase4(&broadcasts, true)
        .expect("sign session phase4 should succeed");

    assert_ne!(signature.r, [0u8; 32]);
    assert_ne!(signature.s, [0u8; 32]);

    let r_hex = hex::encode(signature.r);
    let s_hex = hex::encode(signature.s);
    assert!(verify_ecdsa_signature(
        &msg_hash,
        &parties[0].pk,
        &r_hex,
        &s_hex,
    ));
}

fn run_complete_refresh(parties: &[Party]) -> Vec<Party> {
    println!("[e2e][refresh] phase1 start");
    let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(SHARE_COUNT as usize);
    for party in parties {
        dkg_1.push(party.refresh_complete_phase1());
    }
    println!("[e2e][refresh] phase1 done");

    let mut poly_fragments = vec![
        Vec::<Scalar>::with_capacity(SHARE_COUNT as usize);
        SHARE_COUNT as usize
    ];
    for row in dkg_1 {
        for j in 0..SHARE_COUNT {
            poly_fragments[j as usize].push(row[j as usize]);
        }
    }

    let mut correction_values = Vec::with_capacity(SHARE_COUNT as usize);
    let mut proofs_commitments = Vec::with_capacity(SHARE_COUNT as usize);
    let mut zero_kept_2to3 = Vec::with_capacity(SHARE_COUNT as usize);
    let mut zero_transmit_2to4 = Vec::with_capacity(SHARE_COUNT as usize);

    println!("[e2e][refresh] phase2 start");
    for i in 0..SHARE_COUNT {
        let (correction_value, proof_commitment, zero_keep, zero_transmit) =
            parties[i as usize].refresh_complete_phase2(&REFRESH_SID, &poly_fragments[i as usize]);
        correction_values.push(correction_value);
        proofs_commitments.push(proof_commitment);
        zero_kept_2to3.push(zero_keep);
        zero_transmit_2to4.push(zero_transmit);
    }
    println!("[e2e][refresh] phase2 done");

    let mut zero_received_2to4 = Vec::with_capacity(SHARE_COUNT as usize);
    for i in 1..=SHARE_COUNT {
        let i_idx = PartyIndex::new(i).unwrap();
        let mut row = Vec::with_capacity((SHARE_COUNT - 1) as usize);
        for party_messages in &zero_transmit_2to4 {
            for message in party_messages {
                if message.parties.receiver == i_idx {
                    row.push(message.clone());
                }
            }
        }
        zero_received_2to4.push(row);
    }

    let mut zero_kept_3to4 = Vec::with_capacity(SHARE_COUNT as usize);
    let mut zero_transmit_3to4 = Vec::with_capacity(SHARE_COUNT as usize);
    let mut mul_kept_3to4 = Vec::with_capacity(SHARE_COUNT as usize);
    let mut mul_transmit_3to4 = Vec::with_capacity(SHARE_COUNT as usize);

    println!("[e2e][refresh] phase3 start");
    for i in 0..SHARE_COUNT {
        let (zero_keep, zero_transmit, mul_keep, mul_transmit) =
            parties[i as usize].refresh_complete_phase3(&REFRESH_SID, &zero_kept_2to3[i as usize]);
        zero_kept_3to4.push(zero_keep);
        zero_transmit_3to4.push(zero_transmit);
        mul_kept_3to4.push(mul_keep);
        mul_transmit_3to4.push(mul_transmit);
    }
    println!("[e2e][refresh] phase3 done");

    let mut zero_received_3to4 = Vec::with_capacity(SHARE_COUNT as usize);
    let mut mul_received_3to4 = Vec::with_capacity(SHARE_COUNT as usize);
    for i in 1..=SHARE_COUNT {
        let i_idx = PartyIndex::new(i).unwrap();

        let mut zero_row = Vec::with_capacity((SHARE_COUNT - 1) as usize);
        for party_messages in &zero_transmit_3to4 {
            for message in party_messages {
                if message.parties.receiver == i_idx {
                    zero_row.push(message.clone());
                }
            }
        }
        zero_received_3to4.push(zero_row);

        let mut mul_row = Vec::with_capacity((SHARE_COUNT - 1) as usize);
        for party_messages in &mul_transmit_3to4 {
            for message in party_messages {
                if message.parties.receiver == i_idx {
                    mul_row.push(message.clone());
                }
            }
        }
        mul_received_3to4.push(mul_row);
    }

    println!("[e2e][refresh] phase4 start");
    let mut refreshed_parties = Vec::with_capacity(SHARE_COUNT as usize);
    for i in 0..SHARE_COUNT {
        let refreshed = parties[i as usize]
            .refresh_complete_phase4(
                &REFRESH_SID,
                &correction_values[i as usize],
                &proofs_commitments,
                &zero_kept_3to4[i as usize],
                &zero_received_2to4[i as usize],
                &zero_received_3to4[i as usize],
                &mul_kept_3to4[i as usize],
                &mul_received_3to4[i as usize],
            )
            .expect("complete refresh phase4 should succeed");
        refreshed_parties.push(refreshed);
    }
    println!("[e2e][refresh] phase4 done");

    refreshed_parties
}

fn derive_child_parties_unhardened(parties: &[Party], path: &str) -> Vec<Party> {
    parties
        .iter()
        .map(|party| {
            party
                .derive_from_path(path)
                .expect("unhardened BIP32 derivation should succeed")
        })
        .collect()
}

#[test]
fn test_e2e_fixed_3of5_dkg_p2wsh_sign_refresh() {
    println!("[e2e] starting fixed 3-of-5 DKG");
    let parties = run_fixed_3of5_dkg();
    println!("[e2e] DKG complete");

    let expected_pk = parties[0].pk;
    let expected_chain_code = parties[0].derivation_data.chain_code;
    for party in &parties {
        assert_eq!(party.pk, expected_pk);
        assert_eq!(party.derivation_data.chain_code, expected_chain_code);
    }

    let child_parties = derive_child_parties_unhardened(&parties, CHILD_DERIVATION_PATH);
    let child_expected_pk = child_parties[0].pk;
    for party in &child_parties {
        assert_eq!(party.pk, child_expected_pk);
    }

    let mainnet_p2wsh = p2wsh_mainnet_from_group_key(&child_parties[0].pk);
    println!("Deterministic 3-of-5 P2WSH: {mainnet_p2wsh}");
    assert!(mainnet_p2wsh.starts_with("bc1q"));
    assert_eq!(mainnet_p2wsh.len(), 62);

    let message_hash = tagged_hash(b"e2e-fixed-sign", &[b"DKLs23 deterministic e2e test"]);
    println!("[e2e] pre-refresh signing start");
    run_sign_with_parties(&child_parties, SIGN_ID_PRE_REFRESH, message_hash);
    println!("[e2e] pre-refresh signing complete");

    println!("[e2e] refresh start");
    let refreshed_parties = run_complete_refresh(&parties);
    println!("[e2e] refresh complete");

    for party in &refreshed_parties {
        assert_eq!(party.pk, expected_pk);
    }

    let refreshed_child_parties =
        derive_child_parties_unhardened(&refreshed_parties, CHILD_DERIVATION_PATH);
    for party in &refreshed_child_parties {
        assert_eq!(party.pk, child_expected_pk);
    }

    let refreshed_p2wsh = p2wsh_mainnet_from_group_key(&refreshed_child_parties[0].pk);
    assert_eq!(refreshed_p2wsh, mainnet_p2wsh);

    println!("[e2e] post-refresh signing start");
    run_sign_with_parties(&refreshed_child_parties, SIGN_ID_POST_REFRESH, message_hash);
    println!("[e2e] post-refresh signing complete");
}
