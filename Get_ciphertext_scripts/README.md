# Get_ciphertext_scripts

These directory contains scripts (written in C and compiled using standard gcc) that perform a brute-force search for chosen ciphertexts that satisfy a certain set of conditions to perform the attack for
the following schemes: `Kyber512`, `LAC128`, `LAC256` and `NewHope512`. While the ciphertexts for `Kyber512`, `LAC128` and `LAC256` are found using exhaustive brute-force search over the reduced ciphertext space, ciphertexts for `NewHope512` are found using a randomized brute-force search due to increased complexity of the ciphertext search space.

## Compilation Commands:

- `make clean`
- `make`

## Run Command:

- `./get_chosen_ct`

## Information about outputs:

### LAC and Kyber

A ciphertext can be identified using as ordered pair (u,v) in the case of Kyber512 or LAC128, while it can be identified using a tuple (u,v1,v2) in the case of NewHope512. The program when run, outputs a
sequence of 0s and 1s denoted as SQ for every tried ciphertext combination. For example, in the case of Kyber512, the output is of the form,  

`Choice_u, Choice_v: 35, 2`

`1, 1, 0, 0, 0,`

This means that the ordered pair `(35,2)` was tried and the sequence SQ `1,1,0,0,0` corresponds to the message output of either m = 0 or m = 1 for the secret coefficient `-2, -1, 0, 1 ,2` in the same order. So, in order to choose the ciphertexts to be used for the attack, we manually have to choose those ciphertexts whose SQs together uniquely identify the secret coefficient.

The chosen ciphertexts for our attack on Kyber512 are

`Choice_u, Choice_v = 210, 1`

`1, 0, 0, 0, 0,`

`Choice_u, Choice_v = 210, 7`

`0, 0, 0, 0, 1`

`Choice_u, Choice_v = 101, 2`

`1, 1, 0, 0, 0`

`Choice_u, Choice_v = 100, 6`

`0, 0, 0, 1, 1`

`Choice_u, Choice_v = 415, 3`

`1, 1, 1, 0, 0`

However, there could exist multiple ciphertexts through which the same attack can be mounted.

### NewHope512
