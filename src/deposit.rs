use anyhow::Ok;
use anyhow::Result;
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::hash_types::MerkleCapTarget;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_proofs::verify_merkle_proof_to_cap;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use crate::types::POSITION_TREE_DEPTH;
use crate::types::ProofTuple;
use crate::types::Transaction;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::Witness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::config::GenericHashOut;


// #[derive(Debug, Clone)]
// pub struct DepositTransaction<F:RichField> {
//     pub balance_before: F,
//     pub root_before: HashOut<F>,
//     pub root_after: HashOut<F>,
//     pub merkle_proof: MerkleProof<F, PoseidonHash>,
//     pub position_index: usize,
//     pub amount: F,
// }


#[derive(Debug, Clone)]
pub struct DepositTargets {
    pub root_before_target: HashOutTarget,
    pub root_after_target: HashOutTarget,
    pub merkle_proof_target: MerkleProofTarget,
    pub balance_before_target: Target,
    pub position_index_target: Target,
    pub amount_target: Target,
}

pub fn deposit_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> , const D: usize>(tree_height: usize, builder: &mut CircuitBuilder<F, D>) -> DepositTargets {
    let root_before_target = builder.add_virtual_hash();

    let root_after_target = builder.add_virtual_hash();

    let merkle_proof_target = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(tree_height),
    };

    let balance_before_target = builder.add_virtual_target();

    let position_index_target = builder.add_virtual_target();
    let position_index_bits = builder.split_le(position_index_target, tree_height);
    
    builder.verify_merkle_proof_to_cap::<PoseidonHash>(
        vec![balance_before_target],
        &position_index_bits,
        &MerkleCapTarget(vec![root_before_target]),
        &merkle_proof_target,
    );

    let amount_target = builder.add_virtual_target();
    let balance_after_target = builder.add(balance_before_target, amount_target);

    builder.verify_merkle_proof_to_cap::<PoseidonHash>(
        vec![balance_after_target],
        &position_index_bits,
        &MerkleCapTarget(vec![root_after_target]),
        &merkle_proof_target,
    );

    builder.register_public_inputs(&root_before_target.elements);
    builder.register_public_inputs(&root_after_target.elements);

    DepositTargets {
        root_before_target,
        root_after_target,
        merkle_proof_target,
        balance_before_target,
        position_index_target,
        amount_target,
    }
}

pub fn make_deposit_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &CircuitConfig,
    deposit_tx: Transaction<F,D>
) ->Result<ProofTuple<F,C,D>> 
    where
    [(); C::Hasher::HASH_SIZE]:,
{

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let deposit_targets = deposit_circuit::<F, C, D>(POSITION_TREE_DEPTH, &mut builder);
    let DepositTargets {
        root_before_target,
        root_after_target,
        merkle_proof_target,
        balance_before_target,
        position_index_target,
        amount_target,
    } = deposit_targets;

    let Transaction {
        transaction_type,
        root_before,
        root_after,
        merkle_proof,
        balance_before,
        position_index,
        amount,
        position_tree_depth,
    } = deposit_tx;

    let mut pw: PartialWitness<F> = PartialWitness::new();
    pw.set_hash_target(root_before_target, root_before);
    pw.set_hash_target(root_after_target, root_after);

    pw.set_target(balance_before_target, balance_before);
    pw.set_target(position_index_target, F::from_canonical_usize(position_index));
    pw.set_target(amount_target, amount);

    for (ht, h) in merkle_proof_target
    .siblings
    .into_iter()
    .zip(merkle_proof.siblings)
    {
        let ho = HashOut::<F>::from_vec(h.to_vec());
        pw.set_hash_target(ht, ho);
    }
    let data = builder.build::<C>();

    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;
    Ok((proof, data.verifier_only, data.common))

    // Ok(())
}




#[cfg(test)]
mod tests {
    use std::{fs::File, path::Path, io::Write};
    use anyhow::Result;

    use plonky2::{plonk::config::{GenericConfig, PoseidonGoldilocksConfig}, fri::{FriConfig, reduction_strategies::FriReductionStrategy}};

    // use crate::{config::KeccakGoldilocksConfig2};
    use crate::{verifier::{generate_proof_base64, generate_verifier_config, generate_circom_verifier}, types::{verify_proof, Cbn128}, sequencer::generate_transactions};
    use crate::recursive::recursive_proof;
    use crate::types::{F, C, D};
    use super::*;


    #[test]
    fn test_deposit_circuit() {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let deposit_targets = deposit_circuit::<F,C,D>(POSITION_TREE_DEPTH, &mut builder);
    }

    #[test]
    fn test_deposit_proof() {
        let standard_config = CircuitConfig::standard_recursion_config();
        let deposit_tx = generate_transactions::<F, D>(vec![0]).unwrap();
        let (pi, vd, cd) = 
            make_deposit_proof::<F, C, D>(&standard_config, deposit_tx[0].clone()).unwrap();
        verify_proof(pi, vd, cd).unwrap();
    }


}

