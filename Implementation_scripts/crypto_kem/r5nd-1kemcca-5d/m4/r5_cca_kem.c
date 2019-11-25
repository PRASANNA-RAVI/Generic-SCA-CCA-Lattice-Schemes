//  Copyright (c) 2019, PQShield Ltd. and Koninklijke Philips N.V.
//  Markku-Juhani O. Saarinen, Koninklijke Philips N.V.

#include "r5_parameter_sets.h"

#ifdef ROUND5_CCA_PKE

#include <stdlib.h>
#include <string.h>

#include "r5_cca_kem.h"
#include "r5_cpa_pke.h"
#include "randombytes.h"
#include "r5_xof.h"
#include "ct_util.h"
#include "hal.h"

// CCA-KEM KeyGen()

#define POLY_MASK_1 0X9ABDCD93
#define POLY_MASK_2 0X91CB0C2C

static int shift_lfsr(unsigned int *lfsr, unsigned int polynomial_mask)
{
  int feedback;

  feedback = *lfsr & 1;
  *lfsr >>= 1;
  if (feedback == 1)
    *lfsr ^= polynomial_mask;
  return *lfsr;
}

static int get_random(void)
{
  static unsigned int lfsr_1 = 0xAABBCCDD;
  static unsigned int lfsr_2 = 0x778800DD;
  shift_lfsr(&lfsr_1, POLY_MASK_1);
  shift_lfsr(&lfsr_2, POLY_MASK_2);
  return ((shift_lfsr(&lfsr_1, POLY_MASK_1) ^ shift_lfsr(&lfsr_2, POLY_MASK_2)) & 0XFF);
}

int r5_cca_kem_keygen(uint8_t *pk, uint8_t *sk)
{
    uint8_t y[PARAMS_KAPPA_BYTES];
    int i;

    /* Generate the base key pair */
    r5_cpa_pke_keygen(pk, sk);

    /* Append y and pk to sk */
    // randombytes(y, PARAMS_KAPPA_BYTES);

    for(i = 0;i<PARAMS_KAPPA_BYTES;i++)
        y[i] = 0xBC;

    memcpy(sk + PARAMS_KAPPA_BYTES, y, PARAMS_KAPPA_BYTES);
    memcpy(sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);

    return 0;
}

// CCA-KEM Encaps()

int r5_cca_kem_encapsulate(uint8_t *ct, uint8_t *k, const uint8_t *pk, int count, int profiling)
{
    int i;

    uint8_t hash_in[PARAMS_KAPPA_BYTES +
        (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES > PARAMS_PK_SIZE ?
            PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES : PARAMS_PK_SIZE)];
    uint8_t m[PARAMS_KAPPA_BYTES];
    uint8_t L_g_rho[3][PARAMS_KAPPA_BYTES];

    // randombytes(m, PARAMS_KAPPA_BYTES); // generate random m

    for(i = 0;i<PARAMS_KAPPA_BYTES;i++)
        m[i] = 0x00;

    memcpy(hash_in, m, PARAMS_KAPPA_BYTES); // G: (l | g | rho) = h(m | pk);
    memcpy(hash_in + PARAMS_KAPPA_BYTES, pk, PARAMS_PK_SIZE);
    r5_hash(L_g_rho, 3 * PARAMS_KAPPA_BYTES, hash_in,
        PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);

    /* Encrypt  */
    r5_cpa_pke_encrypt(ct, pk, m, L_g_rho[2], count, profiling); // m: ct = (U,v)

    // send_USART_bytes(ct,CRYPTO_CIPHERTEXTBYTES);

    /* Append g: ct = (U,v,g) */
    memcpy(ct + PARAMS_CT_SIZE, L_g_rho[1], PARAMS_KAPPA_BYTES);

    /* k = H(L, ct) */
    memcpy(hash_in, L_g_rho[0], PARAMS_KAPPA_BYTES);
    memcpy(hash_in + PARAMS_KAPPA_BYTES,
            ct, PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    r5_hash(k, PARAMS_KAPPA_BYTES, hash_in,
        PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);

    return 0;
}

// CCA-KEM Decaps()

int r5_cca_kem_decapsulate(uint8_t *k, const uint8_t *ct, const uint8_t *sk)
{
    uint8_t hash_in[PARAMS_KAPPA_BYTES + (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES > PARAMS_PK_SIZE ? PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES : PARAMS_PK_SIZE)];
    uint8_t m_prime[PARAMS_KAPPA_BYTES];
    uint8_t L_g_rho_prime[3][PARAMS_KAPPA_BYTES];
    uint8_t ct_prime[PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES];
    uint8_t fail;

    r5_cpa_pke_decrypt(m_prime, sk, ct); // r5_cpa_pke_decrypt m'

    memcpy(hash_in, m_prime, PARAMS_KAPPA_BYTES);
    memcpy(hash_in + PARAMS_KAPPA_BYTES, // (L | g | rho) = h(m | pk)
            sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, PARAMS_PK_SIZE);
    r5_hash(L_g_rho_prime, 3 * PARAMS_KAPPA_BYTES, hash_in,
        PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE);

    // Encrypt m: ct' = (U',v')
    r5_cpa_pke_encrypt_cmp(ct_prime, sk + PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES, m_prime, L_g_rho_prime[2]);

    // ct' = (U',v',g')
    memcpy(ct_prime + PARAMS_CT_SIZE, L_g_rho_prime[1], PARAMS_KAPPA_BYTES);

    // k = H(L', ct')
    memcpy(hash_in, L_g_rho_prime[0], PARAMS_KAPPA_BYTES);
    // verification ok ?
    fail = ct_memcmp(ct, ct_prime,
        PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);

    // k = H(y, ct') depending on fail state
    ct_cmov(hash_in, sk + PARAMS_KAPPA_BYTES, PARAMS_KAPPA_BYTES, fail);

    memcpy(hash_in + PARAMS_KAPPA_BYTES, ct_prime,
        PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);
    r5_hash(k, PARAMS_KAPPA_BYTES, hash_in,
        PARAMS_KAPPA_BYTES + PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES);

    return 0;
}

#endif /* ROUND5_CCA_PKE */
