#include "indcpa.h"
#include "ntt.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"
#include "reduce.h"
#include "hal.h"
#include <string.h>
#include <stdint.h>

extern void doublebasemul_asm(int16_t *r, const int16_t *a, const int16_t *b, int16_t zeta);
/*************************************************
* Name:        matacc
*
* Description: Multiplies a row of A or A^T, generated on-the-fly,
*              with a vector of polynomials and accumulates into the result.
*
* Arguments:   - poly *r:                    pointer to output polynomial to accumulate in
*              - polyvec *b:                 pointer to input vector of polynomials to multiply with
*              - unsigned char i:            byte to indicate the index < KYBER_K of the row of A or A^T
*              - const unsigned char *seed:  pointer to the public seed used to generate A
*              - int transposed:             boolean indicatin whether A or A^T is generated
**************************************************/
static void matacc(poly* r, polyvec *b, unsigned char i, const unsigned char *seed, int transposed) {
  unsigned char buf[XOF_BLOCKBYTES+1];
  xof_state state;
  int ctr, pos, k;
  uint16_t val;
  int16_t c[4], tmp[4];

  poly_zeroize(r);

  for(int j=0;j<KYBER_K;j++) {
    ctr = pos = 0;
    if (transposed)
      xof_absorb(&state, seed, i, j);
    else
      xof_absorb(&state, seed, j, i);

    xof_squeezeblocks(buf, 1, &state);

    while (ctr < KYBER_N/4)
    {
      k = 0;
      while(k < 4) {
        val = buf[pos] | ((uint16_t)buf[pos + 1] << 8);
        if (val < 19 * KYBER_Q) {
          val -= (val >> 12) * KYBER_Q; // Barrett reduction
          c[k++] = (int16_t) val;
        }

        pos += 2;
        if (pos + 2 > XOF_BLOCKBYTES) {
          xof_squeezeblocks(buf, 1, &state);
          pos = 0;
        }
      }

      doublebasemul_asm(tmp, &b->vec[j].coeffs[4*ctr], c, zetas[64+ctr]);
      r->coeffs[4*ctr]   += tmp[0];
      r->coeffs[4*ctr+1] += tmp[1];
      r->coeffs[4*ctr+2] += tmp[2];
      r->coeffs[4*ctr+3] += tmp[3];
      ctr++;
    }
    poly_reduce(r);
  }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - unsigned char *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(unsigned char *pk, unsigned char *sk) {
    polyvec skpv;
    poly e, pkp;
    unsigned char buf[2 * KYBER_SYMBYTES];
    unsigned char *publicseed = buf;
    unsigned char *noiseseed = buf + KYBER_SYMBYTES;
    int i,j;
    unsigned char nonce = 0;

    // randombytes(buf, KYBER_SYMBYTES);

    for(i = 0;i<KYBER_SYMBYTES;i++)
        buf[i] = 0xAA;

    hash_g(buf, buf, KYBER_SYMBYTES);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(skpv.vec + i, noiseseed, nonce++);

    polyvec_ntt(&skpv);

    for (i = 0; i < KYBER_K; i++) {
        matacc(&pkp, &skpv,i, publicseed, 0);
        poly_frommont(&pkp);

        poly_getnoise(&e, noiseseed, nonce++);
        poly_ntt(&e);
        poly_add(&pkp, &pkp, &e);
        poly_reduce(&pkp);

        poly_tobytes(pk+i*KYBER_POLYBYTES, &pkp);
    }

    polyvec_tobytes(sk, &skpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES); // Pack the public seed in the public key
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
*              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
**************************************************/
void indcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins, int count, int profiling)
{
    polyvec sp;
    poly bp;
    poly *pkp = &bp;
    poly *k = &bp;
    poly *v = &sp.vec[0];
    const unsigned char *seed = pk+KYBER_POLYVECBYTES;
    int i, j;
    unsigned char nonce = 0;

    int count_div = (int)((count)/5) ;
    int count_poly = (int)((count)/(KYBER_N*5));

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(sp.vec + i, coins, nonce++);

    polyvec_ntt(&sp);

    for (i = 0; i < KYBER_K; i++)
    {
        matacc(&bp, &sp, i, seed, 1);
        poly_invntt(&bp);

        poly_addnoise(&bp, coins, nonce++);
        poly_reduce(&bp);

        for(j=0;j<KYBER_N;j++)
        {
            bp.coeffs[j] = 0;
        }

        if(i == count_poly)
        {
            if(count%5 == 0)
            {
                if(profiling == 1 || profiling == 2)
                {
                    bp.coeffs[count_div] = 0;
                }
                else if(profiling == 0)
                    bp.coeffs[count_div] = 210;
            }
            else if(count%5 == 1)
                bp.coeffs[count_div] = 210;
            else if(count%5 == 2)
                bp.coeffs[count_div] = 101;
            else if(count%5 == 3)
                bp.coeffs[count_div] = 100;
            else if(count%5 == 4)
                bp.coeffs[count_div] = 415;
        }

        poly_packcompress(c, &bp, i);
    }


    poly_frombytes(pkp, pk);
    poly_basemul(v, pkp, &sp.vec[0]);
    for (i = 1; i < KYBER_K; i++)
    {
        poly_frombytes(pkp, pk + i*KYBER_POLYBYTES);
        poly_basemul_acc(v, pkp, &sp.vec[i]);
    }

    poly_invntt(v);

    poly_addnoise(v, coins, nonce++);

    poly_frommsg(k, m);
    poly_add(v, v, k);

    for(j=0;j<KYBER_N;j++)
    {
      v->coeffs[j] = 0;
    }

    if(count%5 == 0)
    {
        if(profiling == 1)
            v->coeffs[0] = 0;
        else if(profiling == 2)
            v->coeffs[0] = KYBER_Q/2;
        else if(profiling == 0)
            v->coeffs[0] = 209;
    }
    else if(count%5 == 1)
        v->coeffs[0] = 2705;
    else if(count%5 == 2)
        v->coeffs[0] = 644;
    else if(count%5 == 3)
        v->coeffs[0] = 2626;
    else if(count%5 == 4)
        v->coeffs[0] = 1041;

    poly_reduce(v);

    poly_compress(c + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        indcpa_enc_cmp
*
* Description: Re-encryption function.
*              Compares the re-encypted ciphertext with the original ciphertext byte per byte.
*              The comparison is performed in a constant time manner.
*
*
* Arguments:   - unsigned char *ct:         pointer to input ciphertext to compare the new ciphertext with (of length KYBER_INDCPA_BYTES bytes)
*              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
* Returns:     - boolean integer indicating that re-encrypted ciphertext is equal to the original ciphertext
**************************************************/
int indcpa_enc_cmp(const unsigned char *c,
                   const unsigned char *m,
                   const unsigned char *pk,
                   const unsigned char *coins)
   {
    unsigned char rc = 0;
    polyvec sp;
    poly bp;
    poly *pkp = &bp;
    poly *k = &bp;
    poly *v = &sp.vec[0];
    const unsigned char *seed = pk+KYBER_POLYVECBYTES;
    int i;
    unsigned char nonce = 0;

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise(sp.vec + i, coins, nonce++);

    polyvec_ntt(&sp);

    for (i = 0; i < KYBER_K; i++)
    {
        matacc(&bp, &sp, i, seed, 1);
        poly_invntt(&bp);

        poly_addnoise(&bp, coins, nonce++);
        poly_reduce(&bp);

        rc |= cmp_poly_packcompress(c, &bp, i);
    }

    poly_frombytes(pkp, pk);
    poly_basemul(v, pkp, &sp.vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        poly_frombytes(pkp, pk + i*KYBER_POLYBYTES);
        poly_basemul_acc(v, pkp, &sp.vec[i]);
    }

    poly_invntt(v);

    poly_addnoise(v, coins, nonce++);
    poly_frommsg(k, m);
    poly_add(v, v, k);
    poly_reduce(v);

    rc |= cmp_poly_compress(c + KYBER_POLYVECCOMPRESSEDBYTES, v);

    return rc;
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
*              - const unsigned char *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
*              - const unsigned char *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
int __attribute__ ((noinline)) indcpa_dec(unsigned char *m,
                                           const unsigned char *c,
                                           const unsigned char *sk) {
    poly mp, skp, bp;
    poly *v = &skp;

    poly_frombytes(&skp, sk);
    poly_unpackdecompress(&bp, c, 0);
    poly_ntt(&bp);
    poly_basemul(&mp, &skp, &bp);
    for(int i = 1; i < KYBER_K; i++) {
        poly_frombytes(&skp, sk + i*KYBER_POLYBYTES);
        poly_unpackdecompress(&bp, c, i);
        poly_ntt(&bp);
        poly_basemul_acc(&mp, &skp, &bp);
    }

    poly_invntt(&mp);
    poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
    poly_sub(&mp, v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
    //
    // int flag = 0;
    // int final_flag = 0;
    //
    // int count_div = (int)((count)/5) ;
    //
    // int count_byte_no = (int)count_div/8;
    // int count_bit_position_in_byte = (int)count_div%8;
    //
    // // for(int i=0;i<KYBER_SYMBYTES;i++)
    // // {
    // //   if(m[count_byte_no] == (1<<(count_bit_position_in_byte)))
    // //   {
    // //       if(m[i] == 0x00)
    // //           flag++;
    // //   }
    // // }
    // //
    // // if(flag == KYBER_SYMBYTES-1)
    // // {
    // //     hal_send_str("Y");
    // //     final_flag = 1;
    // // }
    // //
    // // flag = 0;
    // //
    // // for(int i=0;i<KYBER_SYMBYTES;i++)
    // // {
    // //     if(m[i] == 0x00)
    // //       flag++;
    // // }
    // //
    // // if(flag == KYBER_SYMBYTES)
    // // {
    // //     hal_send_str("Z");
    // //     final_flag = 2;
    // // }
    //
    // for(int i=0;i<KYBER_SYMBYTES;i++)
    // {
    //   if(m[0] == 0x01)
    //   {
    //       if(m[i] == 0x00)
    //           flag++;
    //   }
    // }
    //
    // if(flag == KYBER_SYMBYTES-1)
    // {
    //     hal_send_str("Y");
    //     final_flag = 1;
    // }
    //
    // flag = 0;
    //
    // for(int i=0;i<KYBER_SYMBYTES;i++)
    // {
    //     if(m[i] == 0x00)
    //       flag++;
    // }
    //
    // if(flag == KYBER_SYMBYTES)
    // {
    //     hal_send_str("Z");
    //     final_flag = 2;
    // }

    return 0;
}
