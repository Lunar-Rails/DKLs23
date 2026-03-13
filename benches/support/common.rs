use std::collections::BTreeMap;
use std::env;
use std::sync::OnceLock;

use dkls23::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment,
    KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23::protocols::dkg_session::DkgSession;
use dkls23::protocols::re_key::re_key;
use dkls23::protocols::sign_session::SignSession;
use dkls23::protocols::signing::{Broadcast3to4, SignData, TransmitPhase1to2, TransmitPhase2to3};
use dkls23::protocols::{Parameters, Party, PartyIndex};
use dkls23::utilities::hashes::{tagged_hash, HashOutput};
use k256::elliptic_curve::Field;
use k256::Scalar;

pub const DEFAULT_THRESHOLD: u8 = 3;
pub const DEFAULT_SHARE_COUNT: u8 = 5;

pub const DKG_SID: [u8; 32] = [0x11; 32];
pub const SIGN_SID: [u8; 32] = [0x22; 32];
pub const REFRESH_SID: [u8; 32] = [0x33; 32];

#[derive(Clone, Copy, Debug)]
pub struct BenchConfig {
    pub threshold: u8,
    pub share_count: u8,
}

static BENCH_CONFIG: OnceLock<BenchConfig> = OnceLock::new();

fn parse_u8_env(name: &str) -> Option<u8> {
    env::var(name).ok().and_then(|value| value.parse::<u8>().ok())
}

pub fn bench_config() -> &'static BenchConfig {
    BENCH_CONFIG.get_or_init(|| {
        let threshold = parse_u8_env("DKLS_BENCH_T").unwrap_or(DEFAULT_THRESHOLD);
        let share_count = parse_u8_env("DKLS_BENCH_N").unwrap_or(DEFAULT_SHARE_COUNT);

        assert!(threshold >= 2, "DKLS_BENCH_T must be >= 2");
        assert!(share_count >= 2, "DKLS_BENCH_N must be >= 2");
        assert!(
            threshold <= share_count,
            "DKLS_BENCH_T must be <= DKLS_BENCH_N"
        );

        BenchConfig {
            threshold,
            share_count,
        }
    })
}

pub fn bench_id() -> String {
    let cfg = bench_config();
    format!("t{}_n{}", cfg.threshold, cfg.share_count)
}

pub fn fixed_parameters() -> Parameters {
    let cfg = bench_config();
    Parameters {
        threshold: cfg.threshold,
        share_count: cfg.share_count,
    }
}

pub fn fixed_message_hash() -> HashOutput {
    tagged_hash(b"bench-sign", &[b"DKLs23 benchmark message"])
}

pub fn baseline_parties_rekey() -> Vec<Party> {
    let parameters = fixed_parameters();
    let secret_key = Scalar::random(&mut dkls23::utilities::rng::get_rng());
    let (parties, _pkg) = re_key(&parameters, &DKG_SID, &secret_key, None);
    parties
}

pub fn run_dkg_once() -> Vec<Party> {
    let parameters = fixed_parameters();
    let share_count = parameters.share_count;

    let mut sessions: Vec<DkgSession> = (1..=share_count)
        .map(|i| DkgSession::new(parameters.clone(), PartyIndex::new(i).unwrap(), DKG_SID.to_vec()))
        .collect();

    let n = share_count as usize;

    let dkg_phase1: Vec<Vec<Scalar>> = sessions.iter().map(DkgSession::phase1).collect();

    let mut poly_fragments = vec![Vec::<Scalar>::with_capacity(n); n];
    for row in dkg_phase1 {
        for j in 0..share_count {
            poly_fragments[j as usize].push(row[j as usize]);
        }
    }

    let mut proofs_commitments: Vec<ProofCommitment> = Vec::with_capacity(n);
    let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    let mut bip_broadcast_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> =
        BTreeMap::new();

    for (i, session) in sessions.iter_mut().enumerate() {
        let (proof_commitment, zero_transmit, bip_broadcast) =
            session.phase2(&poly_fragments[i]).expect("dkg phase2");
        proofs_commitments.push(proof_commitment);
        zero_transmit_2to4.push(zero_transmit);
        bip_broadcast_2to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
    }

    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for i in 1..=share_count {
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

    for (i, session) in sessions.iter_mut().enumerate() {
        let (zero_transmit, mul_transmit, bip_broadcast) = session.phase3().expect("dkg phase3");
        zero_transmit_3to4.push(zero_transmit);
        mul_transmit_3to4.push(mul_transmit);
        bip_broadcast_3to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
    }

    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4>> = Vec::with_capacity(n);
    for i in 1..=share_count {
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
            .expect("dkg phase4");
        parties.push(party);
    }

    parties
}

pub fn run_sign_once(parties: &[Party], sign_id: [u8; 32], msg_hash: HashOutput) {
    let signers: Vec<u8> = (1..=bench_config().threshold).collect();

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

        let (session, transmit) =
            SignSession::new(&parties[(party_index - 1) as usize], data).expect("sign phase1");
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
            .expect("session")
            .phase2(received_1to2.get(&party_index).expect("received"))
            .expect("sign phase2");
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

    let mut broadcasts: Vec<Broadcast3to4> = Vec::with_capacity(bench_config().threshold as usize);
    for party_index in signers.clone() {
        let broadcast = sessions
            .get_mut(&party_index)
            .expect("session")
            .phase3(received_2to3.get(&party_index).expect("received"))
            .expect("sign phase3");
        broadcasts.push(broadcast);
    }

    let leader = signers[0];
    let signature = sessions
        .remove(&leader)
        .expect("leader session")
        .phase4(&broadcasts, true)
        .expect("sign phase4");

    assert_ne!(signature.r, [0u8; 32]);
    assert_ne!(signature.s, [0u8; 32]);
}

pub fn run_refresh_complete_once(parties: &[Party]) -> Vec<Party> {
    let share_count = bench_config().share_count;

    let mut dkg_1: Vec<Vec<Scalar>> = Vec::with_capacity(share_count as usize);
    for party in parties {
        dkg_1.push(party.refresh_complete_phase1());
    }

    let mut poly_fragments = vec![
        Vec::<Scalar>::with_capacity(share_count as usize);
        share_count as usize
    ];
    for row in dkg_1 {
        for j in 0..share_count {
            poly_fragments[j as usize].push(row[j as usize]);
        }
    }

    let mut correction_values = Vec::with_capacity(share_count as usize);
    let mut proofs_commitments = Vec::with_capacity(share_count as usize);
    let mut zero_kept_2to3: Vec<BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>> =
        Vec::with_capacity(share_count as usize);
    let mut zero_transmit_2to4 = Vec::with_capacity(share_count as usize);

    for i in 0..share_count {
        let (correction_value, proof_commitment, zero_keep, zero_transmit) =
            parties[i as usize].refresh_complete_phase2(&REFRESH_SID, &poly_fragments[i as usize]);
        correction_values.push(correction_value);
        proofs_commitments.push(proof_commitment);
        zero_kept_2to3.push(zero_keep);
        zero_transmit_2to4.push(zero_transmit);
    }

    let mut zero_received_2to4 = Vec::with_capacity(share_count as usize);
    for i in 1..=share_count {
        let i_idx = PartyIndex::new(i).unwrap();
        let mut row = Vec::with_capacity((share_count - 1) as usize);
        for party_messages in &zero_transmit_2to4 {
            for message in party_messages {
                if message.parties.receiver == i_idx {
                    row.push(message.clone());
                }
            }
        }
        zero_received_2to4.push(row);
    }

    let mut zero_kept_3to4: Vec<BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>> =
        Vec::with_capacity(share_count as usize);
    let mut zero_transmit_3to4 = Vec::with_capacity(share_count as usize);
    let mut mul_kept_3to4: Vec<BTreeMap<PartyIndex, KeepInitMulPhase3to4>> =
        Vec::with_capacity(share_count as usize);
    let mut mul_transmit_3to4 = Vec::with_capacity(share_count as usize);

    for i in 0..share_count {
        let (zero_keep, zero_transmit, mul_keep, mul_transmit) =
            parties[i as usize].refresh_complete_phase3(&REFRESH_SID, &zero_kept_2to3[i as usize]);
        zero_kept_3to4.push(zero_keep);
        zero_transmit_3to4.push(zero_transmit);
        mul_kept_3to4.push(mul_keep);
        mul_transmit_3to4.push(mul_transmit);
    }

    let mut zero_received_3to4 = Vec::with_capacity(share_count as usize);
    let mut mul_received_3to4 = Vec::with_capacity(share_count as usize);
    for i in 1..=share_count {
        let i_idx = PartyIndex::new(i).unwrap();

        let mut zero_row = Vec::with_capacity((share_count - 1) as usize);
        for party_messages in &zero_transmit_3to4 {
            for message in party_messages {
                if message.parties.receiver == i_idx {
                    zero_row.push(message.clone());
                }
            }
        }
        zero_received_3to4.push(zero_row);

        let mut mul_row = Vec::with_capacity((share_count - 1) as usize);
        for party_messages in &mul_transmit_3to4 {
            for message in party_messages {
                if message.parties.receiver == i_idx {
                    mul_row.push(message.clone());
                }
            }
        }
        mul_received_3to4.push(mul_row);
    }

    let mut refreshed_parties = Vec::with_capacity(share_count as usize);
    for i in 0..share_count {
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
            .expect("refresh complete phase4");
        refreshed_parties.push(refreshed);
    }

    refreshed_parties
}
