# Generic Side-channel attacks on CCA-secure lattice-based PKE and KEM schemes

This project contains the implementation and attack scripts required to perform
generic side-channel assisted chosen-ciphertext attacks over several lattice-based PKE and KEM
schemes. In particular, we include scripts for lattice-based PKE and KEM schemes such as Kyber, LAC, Round5 and NewHope. The main project contains three sub-directories.

## Get_ciphertext_scripts

This directory contains scripts that search for suitable ciphertexts to perform side-channel assisted chosen ciphertext attacks over the CCA-seucre Kyber, LAC and NewHope KEM schemes. The scripts perform a brute-force/randomized search for the ciphertexts which satisfy a certain set of conditions, depending on the scheme.

## Implementation_scripts

This directory contains the implementation scripts for three schemes in particular: Kyber512, LAC128 and Round5 (R5ND_1kemcca_5d). The implementations are part of the
**pqm4** library, a benchmarking and testing framework for PQC schemes on the ARM Cortex-M4
microcontroller. The implementation scripts have been modified appropriately for easy acquisition of
traces to perform the chosen-ciphertext attack with pre-computed chosen-ciphertexts. More details to perform trace acquisition are provided inside the directory.

## Attack_scripts

This directory contains side-channel traces corresponding to the targeted operations within various schemes and the MATLAB scripts to perform the attack using the side-channel traces.

## Attack_Simulations (NewHope)

This directory contains plaintext oracle based chosen ciphertext attack simulations on both variants of NewHope (NewHope512 and NewHope1024) which are written completely in C.

## License
All code in this repository is released under the conditions of [CC0](http://creativecommons.org/publicdomain/zero/1.0/).
