# Attack_scripts

This directory contains attack traces and scripts to carry out the attack for three schemes: `Kyber512`, `LAC128` and `R5ND_1kemcca_5d`. There are three trace sets. Two trace sets contain
pre-processing traces corresponding to the decrypted message (for Kyber) or codeword (for LAC and Round5) m=0 and m=1 respectively. Each trace set has about 50 traces each. The third trace set has the traces to perform key recovery. The attack script for each scheme is present in the (.m) MATLAB file. The correct secret key used during the attack is stored in a `.dat` file in the respective directories. The MATLAB file uses the correct secret key to deduce the success rate of the attack.

## Two types of attacks:

There are two types of attacks implemented in two attack scripts. In both the techniques, t-test is first employed between the two trace sets of the pre-processing phase to choose the points of interest (PoI) on the trace distinguishing the two classes (c/m = 0 or 1). Subsequently, two different techniques to classify based on how the points of interest (PoI) are handled.

- `t-test based reduced template technique`: In this technique, we use the PoI to build template for each class and compute their means as reduced templates. In the attack phase, we perform the least sum-of-squared difference test to determine the class.

- `t-test based clustering technique`: In this technique, we compute the mean of PoI of each trace in the trace set of the pre-processing phase. If we plot the mean of PoI of every trace, we can obtain a clear clustering based on the class to which the trace belongs... Now, in the attack phase, we can simply compute the mean of PoI of the trace to be classified and then decide the class based on the cluster to which the mean belongs to.

# Schemes Targeted:

## Kyber512

Trace set for attack is split into two folders, with each folder corresponding to traces for recovery of each polynomial of the secret module of Kyber. Each trace file in the trace set consists of five traces to recover the corresponding secret coefficient.

## LAC128

Trace set for attack is present in a single folder with each trace file consisting of two traces to recover the corresponding secret coefficient.

## R5ND_1kemcca_5d

Trace set for attack is present in a single folder with each trace file consisting of two traces to recover the corresponding secret coefficient.
