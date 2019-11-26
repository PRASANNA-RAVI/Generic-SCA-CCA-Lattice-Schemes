# Get_ciphertext_scripts

These directory contains scripts (written in C and compiled using standard gcc) that perform a brute-force search for chosen ciphertexts that satisfy a certain set of conditions to perform the attack for
the following schemes: `Kyber512`, `LAC128`, `LAC256` and `NewHope512`. While the ciphertexts for `Kyber512`, `LAC128` and `LAC256` are found using exhaustive brute-force search over the reduced ciphertext space, ciphertexts for `NewHope512` are found using a randomized brute-force search due to increased complexity of the ciphertext search space.

## Compilation Commands:

- `make clean`
- `make`

## Run Command:

- `./get_chosen_ct`

## Information about outputs:

### LAC128 and Kyber512

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

However, there could exist multiple ciphertexts through which the same attack can be mounted. The ciphertexts chosen for our attack (embedded in the implementation scripts) are present in text files `lac_128_ct.txt` for LAC128, `lac_256_ct.txt` for LAC256 and `Kyber_ct.txt` for Kyber512 in the respective folders.

### NewHope512

The chosen ciphertext search space for our attack on NewHope512 is too high to be brute-forced. Hence,
we perform a randomized search for the chosen ciphertexts. Moreover, the ciphertexts are used in the attack
to distinguish between coefficient pairs. Our script initially collects about 100 ciphertexts to distinguish between the secret coefficient pairs and enumerates which coefficient pairs still need new ciphertexts for
distinguishability. Then, the script tries to resolve the conflict between the remaining coefficient pairs which are yet to be distinguished and only terminates when each coefficient pair can be uniquely distinguished.

The different components (u,v1,v2) of the tuple are stored in different text
files `u_values.txt`, `v_1_values.txt` and `v_2_values.txt`. The corresponding 0/1 sequence SQ for the 100
chosen ciphertexts are stored in `bits_values.txt`.

Since the coefficients can take values between [-8,8], there are 289 coefficient pairs to be
distinguished. Each coefficient pair is enumerated from 0 to 288 with 0 denoting the coefficient pair [-8,-8]
and 288 denoting [8,8]. The unresolved coefficient pairs are actually stored in colliding_rows.dat where
enumerated coefficient pairs in the same row denoted indistinguishable pairs after collection of 100 ciphertexts. Thus, the program tries to resolve the conflict between the indistinguishable coefficient pairs, two pairs at a time. As the program resolves the conflict between the indistinguishable coefficient pairs,
the new ciphertexts are simply appended to the same files `u_values.txt`, `v_1_values.txt` and `v_2_values.txt` which stored the value of the 100 initially chosen ciphertexts.
