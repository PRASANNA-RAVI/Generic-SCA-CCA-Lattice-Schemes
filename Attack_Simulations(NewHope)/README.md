# Attack_Simulations (NewHope)

This directory contains attack simulations for NewHope512 and NewHope1024. The scripts are separately written
for both variants of NewHope. They allow to generate ciphertexts for the attack and also to perform attack on the reference implementation of NewHope submitted to the second round of the NIST standardization process. Please use the `make help` command to get information on run the scripts. The scripts are also appropriately commented for better code readability. The script involves a lot of file handling and hence runs slowly, especially for NewHope1024. The script is not optimized for memory usage and hence we would also advise to increase the stack usage limit to the maximum possible so that it does not result in any segmentation faults.
This can be done using terminal commands such as `ulimit -u unlimited` on MAC. Please note that retrieval of the secret key for NewHope1024 is significantly slower compared to NewHope512.
