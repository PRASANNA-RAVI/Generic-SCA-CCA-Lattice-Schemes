#ifndef PQCLEAN_LEDAKEMLT12_LEAKTIME_API_H
#define PQCLEAN_LEDAKEMLT12_LEAKTIME_API_H

#include <stdint.h>

#define PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_SECRETKEYBYTES  26
#define PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_PUBLICKEYBYTES  6520
#define PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_CIPHERTEXTBYTES 6520
#define PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_BYTES           32

#define PQCLEAN_LEDAKEMLT12_LEAKTIME_CRYPTO_ALGNAME "LEDAKEMLT12"

int PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_LEDAKEMLT12_LEAKTIME_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);


#endif
