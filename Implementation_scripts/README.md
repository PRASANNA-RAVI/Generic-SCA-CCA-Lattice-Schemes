# Implementation_scripts:

This directory contains the implementation scripts for the schemes `Kyber512`, `LAC128` and `R5ND_1kemcca_5d` which can run on the STM32F407VG microcontroller based on the ARM Cortex-M4 microcontroller. The scripts help in performing trace acquisition of the target operations within the aforementioned schemes. This directory has the same directory structure as the **pqm4** library. Hence, instructions to run the code can be referred to from the github page **pqm4**. The implementations are written to work with a fixed secret key. It is also important to note that the chosen ciphertexts to perform the pre-processing and attack phase for each scheme is already hardcoded into the implementation. The key generation phase is computed once with the fixed key, however the decapsulation phase can be triggered multiple times with the hardcoded chosen ciphertexts. However, users can modify both the secret key and chosen ciphertexts to test repeatability of the attack.

# Compilation Commands:

- `Kyber512`        : make IMPLEMENTATION_PATH=crypto_kem/kyber512/m4 bin/crypto_kem_kyber512_m4_test.bin
- `LAC128`          : make IMPLEMENTATION_PATH=crypto_kem/lac128/ref bin/crypto_kem_lac128_ref_test.bin
- `R5ND_1kemcca-5d` : make IMPLEMENTATION_PATH=crypto_kem/r5nd-1kemcca-5d/m4 bin/crypto_kem_r5nd-1kemcca-5d_m4_test.bin

The respective binaries to be flashed will be present in the /bin folder which is created upon compilation.

## Communication with the board:

The UART interface is utilized for communication and synchronization when performing trace-acquisition.
The device can be triggered by feeding either the character `O`, `X` or `S` through the UART interface.
Each character triggers the device into performing the following operations. The device upon completion of the operation outputs the character "Z" through the UART interface. This can be used to synchronize with the device to perform trace-acquisition.

- `O`: Computes the decapsulation operation for a chosen ciphertext corresponding to m = 0 irrespective of the value of the secret key.

- `X`: Computes the decapsulation operation for a chosen ciphertext corresponding to m = 1 irrespective of the value of the secret key.

- `S`: Computes the decapsulation operation for a given chosen ciphertext to recover the secret key one coefficient at a time.

This communication protocol is implemented in the wrapper script `test.c` present in the `mupq/crypto_kem/` folder.

## Trigger for Trace-Acquisition:

GPIO triggers have been embedded into the program which indicate the start and end of sensitive operations whose side-channel measurements are to be captured. The GPIO trigger does high
upon start of computation of the target operation and goes low upon completion of the same computation. GPIO7 on the STM32F4 discovery board has been used as the trigger, which can be input to an oscilloscope for trace capture corresponding to the target operation.

## Steps to perform the attack:

- **Pre-Processing Phase**: Certain number of traces corresponding to both m = 0 and m = 1 should be captured as part of the pre-processing phase. If 50 traces each are to be captured for m = 0 and m = 1,
then send `O` and `X` 50 times each through the UART interface and wait for the completion symbol `Z` each time for synchronization.

- **Attack Phase**: The number of traces required for the attack phase differs based on the scheme. The number of traces can be computed as the product of `Number of coefficients to recover (CO)` and `Number of ciphertexts for each coefficient (CT)`. For `Kyber512`: `CO = 512` and `CT = 5`. For `LAC128`: `CO = 512` and `CT = 2`. For `R5ND_1kemcca_5d`: `CO = 490` and `CT = 2`. The attacker can repeat the attack phase many number of times and take majority voting for high confidence on the recovered key.
