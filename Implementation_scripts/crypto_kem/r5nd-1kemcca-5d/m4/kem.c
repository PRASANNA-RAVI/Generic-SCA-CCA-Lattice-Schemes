//  kem.c
//  Copyright (c) 2019, PQShield Ltd. and Koninklijke Philips N.V.

//  Implementation of NIST KEM API

#include "r5_parameter_sets.h"
#include "nist_kem.h"
#include "r5_cca_kem.h"

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk)
{
    return r5_cca_kem_keygen(pk, sk);
}

int crypto_kem_enc(uint8_t *ct, uint8_t *k, const uint8_t *pk, int count, int profiling)
{
    return r5_cca_kem_encapsulate(ct, k, pk, count, profiling);
}

int crypto_kem_dec(uint8_t *k, const uint8_t *ct, const uint8_t *sk)
{
    return r5_cca_kem_decapsulate(k, ct, sk);
}
