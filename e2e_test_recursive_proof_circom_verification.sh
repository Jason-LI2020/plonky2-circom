echo "****GENERATING RECURSIVE PLONKY2 PROOF****"
cargo test -r --color=always --package plonky2_circom_verifier --lib test::tests::test_resursive_single_proof_to_circom --no-fail-fast -- -Z unstable-options --show-output
echo "DONE ($((end - start))s)"
cd circom/e2e_tests && ./run.sh && cd .. && cd ..


echo "****GENERATING A NEW RECURSIVE PLONKY2 PROOF****"
cargo test -r --color=always --package plonky2_circom_verifier --lib test::tests::test_resursive_single_proof_to_circom --no-fail-fast -- -Z unstable-options --show-output
cd circom/e2e_tests && ./run2.sh && cd .. && cd ..
