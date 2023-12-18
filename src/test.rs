#[cfg(test)]
mod tests {
    use std::{fs::File, path::Path, io::Write};
    use anyhow::Result;

    use plonky2::{plonk::{config::{GenericConfig, PoseidonGoldilocksConfig}, circuit_data::CircuitConfig, circuit_builder::CircuitBuilder}, fri::{FriConfig, reduction_strategies::FriReductionStrategy}};

    // use crate::{config::KeccakGoldilocksConfig2};
    use crate::{verifier::{generate_proof_base64, generate_verifier_config, generate_circom_verifier}, types::{verify_proof, Cbn128, POSITION_TREE_DEPTH}, sequencer::generate_transactions};
    use crate::recursive::recursive_proof;
    use crate::types::{F, C, D};
    use crate::deposit::{deposit_circuit, make_deposit_proof};

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
        let deposit_tx = generate_transactions::<F, D>(vec![0]).unwrap();

        // println!("deposit_tx: {:?}", deposit_tx);

        let (pi, vd, cd) = 
            make_deposit_proof::<F, C, D>(&high_rate_config, deposit_tx[0].clone()).unwrap();
        
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

}