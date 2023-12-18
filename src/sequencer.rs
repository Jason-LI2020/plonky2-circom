use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use rand::Rng;
use anyhow::Result;

use crate::types::{Transaction, ILLEGAL_DEPOSIT};

use crate::types::{VDProof, DEPOSIT, WITHDRAW, RECURSIVE0, RECURSIVE1, POSITION_TREE_DEPTH};

use crate::types::{F, C, D, verify_proof};


pub fn generate_transactions<F: RichField + Extendable<D>, const D: usize>(transaction_sequence: Vec<usize>) -> Result<Vec<Transaction<F, D>>> {
    let mut transactions = Vec::new();

    let n:u64 = 1 << POSITION_TREE_DEPTH;
    // let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_arr()).collect();

    let mut positions = vec![vec![F::from_canonical_u64(100)]; n as usize];
    let mut positions_tree = MerkleTree::<F, PoseidonHash>::new(positions.clone(), 0);
    let amount = F::ONE;
    let position_index: usize = 10;
    for i in transaction_sequence {
        let balance = positions_tree.get(position_index)[0];
        let r0 = positions_tree.cap.0[0];
        let mk_proof = positions_tree.prove(position_index);

        // 0: deposit， 1: withdraw
        match i {
            DEPOSIT => {
                positions[position_index][0] += amount;
                positions_tree = MerkleTree::<F, PoseidonHash>::new(positions.clone(), 0);
                let r1 = positions_tree.cap.0[0];
                let deposit_tx = Transaction{
                    transaction_type: DEPOSIT,
                    root_before: r0,
                    root_after: r1,
                    merkle_proof: mk_proof,
                    balance_before: balance,
                    position_index: position_index,
                    amount: amount,
                    position_tree_depth: POSITION_TREE_DEPTH,
                    // vd_deposit_proof: vd_proofs[DEPOSIT].clone(),
                };
                transactions.push(deposit_tx);
            },
            WITHDRAW => {
                positions[position_index][0] -= amount;
                positions_tree = MerkleTree::<F, PoseidonHash>::new(positions.clone(), 0);
                let r1 = positions_tree.cap.0[0];
                let withdraw_tx = Transaction{
                    transaction_type: WITHDRAW,
                    root_before: r0,
                    root_after: r1,
                    merkle_proof: mk_proof,
                    balance_before: balance,
                    position_index: position_index,
                    amount: amount,
                    position_tree_depth: POSITION_TREE_DEPTH,
                    // vd_deposit_proof: vd_proofs[WITHDRAW].clone(),
                };
                transactions.push(withdraw_tx);
            },
            // ILLEGAL_DEPOSIT => {
            //     positions[position_index][0] *= amount;
            //     positions_tree = PositionSet(MerkleTree::new(positions.clone(), 0));
            //     let r1 = positions_tree.0.cap.0[0];
            //     let illegal_deposit_tx = Transaction{
            //         transaction_type: ILLEGAL_DEPOSIT,
            //         root_before: r0,
            //         root_after: r1,
            //         merkle_proof: mk_proof,
            //         balance_before: balance,
            //         position_index: position_index,
            //         amount: amount,
            //         position_tree_depth: POSITION_TREE_DEPTH,
            //         vd_deposit_proof: vd_proofs[DEPOSIT].clone(),
            //     };
            //     transactions.push(illegal_deposit_tx);
            // },
            _ => panic!("invalid transaction type"),
        }

    };

    Ok(transactions)


}

#[cfg(test)]
mod tests{
    use plonky2::hash::{merkle_proofs::MerkleProof, hash_types::HashOut};
    use super::*;

    #[test]
    fn test_generate_txs() {
        let vd_proof = VDProof{
            merkle_proof: MerkleProof{siblings: vec![]},
            index: F::from_canonical_u64(0),
            root: HashOut::default(),
        };
        // let vd_proofs = vec![vd_proof; 4];
        let sequency = vec![0, 0, 1, 1];
        let txs = generate_transactions::<F,D>(sequency).unwrap();
        assert_eq!(txs.len(), 4);
    }
}
