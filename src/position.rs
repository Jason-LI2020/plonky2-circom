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
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::Witness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::config::GenericHashOut;


#[derive(Debug, Clone)]
pub struct DepositTransaction<F:RichField> {
    pub balance_before: F,
    pub root_before: HashOut<F>,
    pub root_after: HashOut<F>,
    pub merkle_proof: MerkleProof<F, PoseidonHash>,
    pub position_index: usize,
    pub amount: F,
}


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

pub fn create_deposit_tx<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>() -> Result<DepositTransaction<F>>
{
    let n:u64 = 1 << POSITION_TREE_DEPTH;

    let mut positions = vec![vec![F::from_canonical_u64(100)]; n as usize];

    let mut positions_tree = MerkleTree::<F, PoseidonHash>::new(positions.clone(), 0);
        // where [(); PoseidonHash::HASH_SIZE]:;
    let amount = F::from_canonical_u64(5);
    let position_index: usize = 10;


    let balance_before = positions_tree.get(position_index)[0];
    let root_before = HashOut::<F>::from_vec(positions_tree.cap.0[0].to_vec());
    let merkle_proof = positions_tree.prove(position_index);
    // verify_merkle_proof_to_cap::<F, C::InnerHasher>(
    //     vec![balance_before],
    //     position_index,
    //     MerkleCap{vec![root_before])},
    //     &merkle_proof,
    // )?;

    // verify_merkle_proof_to_cap(positions[position_index].clone(), position_index, &positions_tree.cap, &merkle_proof)?;
    // println!("mk proof verified");


    positions[position_index][0] += amount;
    positions_tree = MerkleTree::<F, PoseidonHash>::new(positions.clone(), 0);
    let root_after = HashOut::<F>::from_vec(positions_tree.cap.0[0].to_vec());
    let balance_after = positions_tree.get(position_index)[0];


    Ok(DepositTransaction{balance_before, root_before, root_after, merkle_proof, position_index, amount})
    
}


// pub fn recursive_proof<
//     F: RichField + Extendable<2>,
//     C: GenericConfig<2, F = F>,
//     InnerC: GenericConfig<2, F = F>,
//     const D: usize,
// >(
//     inner_proof: ProofWithPublicInputs<F, InnerC, 2>,
//     inner_vd: VerifierOnlyCircuitData<InnerC, 2>,
//     inner_cd: CommonCircuitData<F, 2>,
//     config: &CircuitConfig,
//     min_degree_bits: Option<usize>,
//     print_gate_counts: bool,
//     print_timing: bool,
// ) -> Result<ProofTuple<F, C, 2>>
// where
//     InnerC::Hasher: AlgebraicHasher<F>,
//     [(); C::Hasher::HASH_SIZE]:,
// {
//     // const D: usize = 2;
//     let mut builder = CircuitBuilder::<F, 2>::new(config.clone());
//     let mut pw = PartialWitness::new();
//     let pt = builder.add_virtual_proof_with_pis(&inner_cd);
//     pw.set_proof_with_pis_target(&pt, &inner_proof);

//     let inner_data = VerifierCircuitTarget {
//         constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
//         circuit_digest: builder.add_virtual_hash(),
//     };
//     pw.set_cap_target(
//         &inner_data.constants_sigmas_cap,
//         &inner_vd.constants_sigmas_cap,
//     );

//     builder.verify_proof(&pt, &inner_data, &inner_cd);

//     if print_gate_counts {
//         builder.print_gate_counts(0);
//     }

//     if let Some(min_degree_bits) = min_degree_bits {
//         // We don't want to pad all the way up to 2^min_degree_bits, as the builder will add a
//         // few special gates afterward. So just pad to 2^(min_degree_bits - 1) + 1. Then the
//         // builder will pad to the next power of two, 2^min_degree_bits.
//         let min_gates = (1 << (min_degree_bits - 1)) + 1;
//         for _ in builder.num_gates()..min_gates {
//             builder.add_gate(NoopGate, vec![]);
//         }
//     }

//     let data = builder.build::<C>();

//     let mut timing = TimingTree::new("prove", Level::Debug);
//     let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
//     if print_timing {
//         timing.print();
//     }

//     println!("######################### recursive verify #########################");
//     data.verify(proof.clone())?;

//     Ok((proof, data.verifier_only, data.common))
// }


pub fn make_deposit_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    config: &CircuitConfig,
    deposit_tx: DepositTransaction<F>
) ->Result<ProofTuple<F,C,D>> 
    where
    [(); C::Hasher::HASH_SIZE]:,
{
    // const D: usize = 2;
    // let mut builder = CircuitBuilder::<F, D>::new(config.clone());

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

    let DepositTransaction {
        balance_before,
        root_before,
        root_after,
        merkle_proof,
        position_index,
        amount,
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
        // println!("ho: {:?}", ho);
        // println!("h: {:?}", h);
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
    use crate::{verifier::{generate_proof_base64, generate_verifier_config, recursive_proof, generate_circom_verifier}, types::{verify_proof, Cbn128}};
    use crate::types::{F, C, D};
    use super::*;


    #[test]
    fn test_create_deposit_tx() {
        let deposit_tx = create_deposit_tx::<F, C, D>().unwrap();
        // println!("deposit_tx: {:?}", deposit_tx);
    }

    #[test]
    fn test_deposit_circuit() {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let deposit_targets = deposit_circuit::<F,C,D>(POSITION_TREE_DEPTH, &mut builder);
    }

    #[test]
    fn test_deposit_proof() {
        let standard_config = CircuitConfig::standard_recursion_config();

        // A high-rate recursive proof, designed to be verifiable with fewer routed wires.
        let high_rate_config = CircuitConfig {
            fri_config: FriConfig {
                rate_bits: 7,
                proof_of_work_bits: 16,
                num_query_rounds: 12,
                ..standard_config.fri_config.clone()
            },
            ..standard_config
        };
        // A final proof, optimized for size.
        let final_config = CircuitConfig {
            num_routed_wires: 37,
            fri_config: FriConfig {
                rate_bits: 8,
                cap_height: 0,
                proof_of_work_bits: 20,
                reduction_strategy: FriReductionStrategy::MinSize(None),
                num_query_rounds: 10,
            },
            ..high_rate_config
        };
        let deposit_tx = create_deposit_tx::<F, C, D>().unwrap();

        // println!("deposit_tx: {:?}", deposit_tx);

        let (pi, vd, cd) = 
            make_deposit_proof::<F, C, D>(&final_config, deposit_tx).unwrap();

        verify_proof(pi, vd, cd).unwrap();
    }

    #[test]
    fn test_resursive_single_proof() {
        let time = std::time::Instant::now();
        let standard_config = CircuitConfig::standard_recursion_config();

        // A high-rate recursive proof, designed to be verifiable with fewer routed wires.
        let high_rate_config = CircuitConfig {
            fri_config: FriConfig {
                rate_bits: 7,
                proof_of_work_bits: 16,
                num_query_rounds: 12,
                ..standard_config.fri_config.clone()
            },
            ..standard_config
        };
        // A final proof, optimized for size.
        let final_config = CircuitConfig {
            num_routed_wires: 37,
            fri_config: FriConfig {
                rate_bits: 8,
                cap_height: 0,
                proof_of_work_bits: 20,
                reduction_strategy: FriReductionStrategy::MinSize(None),
                num_query_rounds: 10,
            },
            ..high_rate_config
        };
        let deposit_tx = create_deposit_tx::<F, C, D>().unwrap();

        // println!("deposit_tx: {:?}", deposit_tx);

        let (pi, vd, cd) = 
            make_deposit_proof::<F, C, D>(&standard_config, deposit_tx).unwrap();
        println!("make_deposit_proof time: {:?}", time.elapsed());


        let (pi, vd, cd) =
        recursive_proof::<F, Cbn128, C, D>(pi, vd, cd, &standard_config, None, true, true).unwrap();
        println!("recursive_proof time: {:?}", time.elapsed());

        verify_proof(pi, vd, cd).unwrap();

    }


    #[test]
    fn test_resursive_single_proof_to_circom() {
        let time = std::time::Instant::now();

        let standard_config = CircuitConfig::standard_recursion_config();

        // A high-rate recursive proof, designed to be verifiable with fewer routed wires.
        let high_rate_config = CircuitConfig {
            fri_config: FriConfig {
                rate_bits: 7,
                proof_of_work_bits: 16,
                num_query_rounds: 12,
                ..standard_config.fri_config.clone()
            },
            ..standard_config
        };
        // A final proof, optimized for size.
        let final_config = CircuitConfig {
            num_routed_wires: 37,
            fri_config: FriConfig {
                rate_bits: 8,
                cap_height: 0,
                proof_of_work_bits: 20,
                reduction_strategy: FriReductionStrategy::MinSize(None),
                num_query_rounds: 10,
            },
            ..high_rate_config
        };
        let deposit_tx = create_deposit_tx::<F, C, D>().unwrap();

        // println!("deposit_tx: {:?}", deposit_tx);

        let (pi, vd, cd) = 
            make_deposit_proof::<F, C, D>(&high_rate_config, deposit_tx).unwrap();
        
        println!("make_deposit_proof time: {:?}", time.elapsed());

        let (pi, vd, cd) =
        recursive_proof::<F, Cbn128, C, D>(pi, vd, cd, &final_config, None, true, true).unwrap();
        println!("recursive_proof time: {:?}", time.elapsed());

        // verify_proof(pi, vd, cd).unwrap();

        let conf = generate_verifier_config(&pi).unwrap();
        let (circom_constants, circom_gates) = generate_circom_verifier(&conf, &cd, &vd).unwrap();

        let mut circom_file = File::create("./circom/circuits/constants.circom").unwrap();
        circom_file.write_all(circom_constants.as_bytes()).unwrap();
        circom_file = File::create("./circom/circuits/gates.circom").unwrap();
        circom_file.write_all(circom_gates.as_bytes()).unwrap();

        let proof_json = generate_proof_base64(&pi, &conf).unwrap();

        if !Path::new("./circom/test/data").is_dir() {
            std::fs::create_dir("./circom/test/data").unwrap();
        }

        let mut proof_file = File::create("./circom/test/data/proof.json").unwrap();
        proof_file.write_all(proof_json.as_bytes()).unwrap();

        let mut conf_file = File::create("./circom/test/data/conf.json").unwrap();
        conf_file.write_all(serde_json::to_string(&conf).unwrap().as_ref()).unwrap();

    }

    // #[test]
    // fn test_deposit_proof_with_solidity_verifier() {
    //     type C = PoseidonGoldilocksConfig;
    //     type F = <C as GenericConfig<2>>::F;
    //     // type KC2 = KeccakGoldilocksConfig2;

    //     const D: usize = 2;
    //     let standard_config = CircuitConfig::standard_recursion_config();

    //     // A high-rate recursive proof, designed to be verifiable with fewer routed wires.
    //     let high_rate_config = CircuitConfig {
    //         fri_config: FriConfig {
    //             rate_bits: 7,
    //             proof_of_work_bits: 16,
    //             num_query_rounds: 12,
    //             ..standard_config.fri_config.clone()
    //         },
    //         ..standard_config
    //     };
    //     // A final proof, optimized for size.
    //     let final_config = CircuitConfig {
    //         num_routed_wires: 37,
    //         fri_config: FriConfig {
    //             rate_bits: 8,
    //             cap_height: 0,
    //             proof_of_work_bits: 20,
    //             reduction_strategy: FriReductionStrategy::MinSize(None),
    //             num_query_rounds: 10,
    //         },
    //         ..high_rate_config
    //     };
    //     let (proof, vd, cd) = 
    //     make_deposit_proof::<C, D>(&standard_config, create_deposit_tx().unwrap()).unwrap();
        
    //     let (proof, vd, cd) =
    //     recursive_proof::<F, C, C, D>(proof, vd, cd, &high_rate_config, None, true, true).unwrap();
        
    //     let (proof, vd, cd) =
    //     recursive_proof::<F, KC2, C, D>(proof, vd, cd, &final_config, None, true, true).unwrap();

    //     let conf = generate_verifier_config(&proof).unwrap();
    //     let (contract, gates_lib, proof_lib) = generate_solidity_verifier(&conf, &cd, &vd).unwrap();

    //     let mut sol_file = File::create("./contract/contracts/Verifier.sol").unwrap();
    //     sol_file.write_all(contract.as_bytes()).unwrap();
    //     sol_file = File::create("./contract/contracts/GatesLib.sol").unwrap();
    //     sol_file.write_all(gates_lib.as_bytes()).unwrap();
    //     sol_file = File::create("./contract/contracts/ProofLib.sol").unwrap();
    //     sol_file.write_all(proof_lib.as_bytes()).unwrap();

    //     let proof_base64 = generate_proof_base64(&proof, &conf).unwrap();
    //     let proof_json = "[ \"".to_owned() + &proof_base64 + &"\" ]";

    //     if !Path::new("./contract/test/data").is_dir() {
    //         std::fs::create_dir("./contract/test/data").unwrap();
    //     }

    //     let mut proof_file = File::create("./contract/test/data/proof.json").unwrap();
    //     proof_file.write_all(proof_json.as_bytes()).unwrap();

    //     let mut conf_file = File::create("./contract/test/data/conf.json").unwrap();
    //     conf_file.write_all(serde_json::to_string(&conf).unwrap().as_ref()).unwrap();

    // }
}

