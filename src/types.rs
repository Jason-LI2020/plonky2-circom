use plonky2::{
        plonk::{
            config::{PoseidonGoldilocksConfig, GenericConfig, GenericHashOut}, 
            proof::ProofWithPublicInputs, 
            circuit_data::{VerifierOnlyCircuitData, CommonCircuitData, VerifierCircuitData}}, 
        hash::{
            merkle_tree::MerkleTree, poseidon::PoseidonHash, 
            merkle_proofs::MerkleProof, hash_types::{HashOut, RichField}
        }, field::{goldilocks_field::GoldilocksField, extension::Extendable}
    };
use plonky2::plonk::config::Hasher;
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::PoseidonBN128GoldilocksConfig;


pub const D: usize = 2;
pub const POSITION_TREE_DEPTH: usize = 10;
pub const DEPOSIT: usize = 0;
pub const WITHDRAW: usize = 1;
pub const RECURSIVE0: usize = 2;
pub const RECURSIVE1: usize = 3;
pub const ILLEGAL_DEPOSIT: usize = 4;


// pub type C = PoseidonBN128GoldilocksConfig;
pub type Cbn128 = PoseidonBN128GoldilocksConfig;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
// pub type Digest = [F; 4];



// pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, 2>;
pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
    // Option<VDProof>,
);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VDProof {
    pub merkle_proof: MerkleProof<GoldilocksField,PoseidonHash>,
    pub index: GoldilocksField,
    pub root: HashOut<GoldilocksField>,
}

#[derive(Debug, Clone)]
pub struct Transaction<F: RichField+ Extendable<D>, const D: usize> {
    pub transaction_type: usize,
    pub root_before: HashOut<F>,
    pub root_after: HashOut<F>,
    pub merkle_proof: MerkleProof<F, PoseidonHash>,
    pub balance_before: F,
    pub position_index: usize,
    pub amount: F,
    pub position_tree_depth: usize,
    // pub vd_deposit_proof: VDProof,
}


// #[derive(Debug, Clone)]
// pub struct PositionSet<F: RichField, C: GenericConfig<D, F = F> >(pub MerkleTree<F, C::Hasher>);
// impl <F: RichField, C: GenericConfig<D, F = F> >PositionSet<F,C> {
//     pub fn tree_height(&self) -> usize {
//         self.0.leaves.len().trailing_zeros() as usize
//     }
// }

pub fn verify_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    proof: ProofWithPublicInputs<F, C, D>, 
    verifier_only: VerifierOnlyCircuitData<C, D>, 
    commom: CommonCircuitData<F, D>) -> Result<()> 
    where [(); C::Hasher::HASH_SIZE]:
    {
    let verifier_data = VerifierCircuitData {
        verifier_only: verifier_only,
        common: commom,
    };

    verifier_data.verify(proof)?;

    println!("Proof verified");
    Ok(())
}


// pub struct Position{
//     pub pubkey: Digest,
//     pub balance: F,
// }