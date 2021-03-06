#include <stdio.h>
#include "api.h"
#include "poly.h"
#include "rng.h"
#include "fips202.h"
#include <math.h>

// Calculate reversebits of a number (Count means the number of bits in the number)
static int reverseBits(int num,int count)
{
    int mask = pow(2,count)-1;
    num = num & mask;
    int reverse_num = 0;
    char bit=0;
    for(int i=count-1;i>=0;i--)
    {
        bit=num&0b1;
        reverse_num = reverse_num + bit*pow(2,i);
        num >>=1;
    }
    return reverse_num;
}

/*************************************************
* Name:        encode_pk
*
* Description: Serialize the public key as concatenation of the
*              serialization of the polynomial pk and the public seed
*              used to generete the polynomial a.
*
* Arguments:   unsigned char *r:          pointer to the output serialized public key
*              const poly *pk:            pointer to the input public-key polynomial
*              const unsigned char *seed: pointer to the input public seed
**************************************************/
static void encode_pk(unsigned char *r, const poly *pk, const unsigned char *seed)
{
  int i;
  poly_tobytes(r, pk);
  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    r[NEWHOPE_POLYBYTES+i] = seed[i];
}

/*************************************************
* Name:        decode_pk
*
* Description: De-serialize the public key; inverse of encode_pk
*
* Arguments:   poly *pk:               pointer to output public-key polynomial
*              unsigned char *seed:    pointer to output public seed
*              const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_pk(poly *pk, unsigned char *seed, const unsigned char *r)
{
  int i;
  poly_frombytes(pk, r);
  for(i=0;i<NEWHOPE_SYMBYTES;i++)
    seed[i] = r[NEWHOPE_POLYBYTES+i];
}

/*************************************************
* Name:        encode_c
*
* Description: Serialize the ciphertext as concatenation of the
*              serialization of the polynomial b and serialization
*              of the compressed polynomial v
*
* Arguments:   - unsigned char *r: pointer to the output serialized ciphertext
*              - const poly *b:    pointer to the input polynomial b
*              - const poly *v:    pointer to the input polynomial v
**************************************************/
static void encode_c(unsigned char *r, const poly *b, const poly *v, int choice_v1, int choice_v2, int choice_v3, int choice_v4)
{
  poly_tobytes(r,b);
  poly_compress(r+NEWHOPE_POLYBYTES, v, choice_v1, choice_v2, choice_v3, choice_v4);
}

/*************************************************
* Name:        decode_c
*
* Description: de-serialize the ciphertext; inverse of encode_c
*
* Arguments:   - poly *b:                pointer to output polynomial b
*              - poly *v:                pointer to output polynomial v
*              - const unsigned char *r: pointer to input byte array
**************************************************/
static void decode_c(poly *b, poly *v, const unsigned char *r)
{
  poly_frombytes(b, r);
  poly_decompress(v, r+NEWHOPE_POLYBYTES);
}

/*************************************************
* Name:        gen_a
*
* Description: Deterministically generate public polynomial a from seed
*
* Arguments:   - poly *a:                   pointer to output polynomial a
*              - const unsigned char *seed: pointer to input seed
**************************************************/
static void gen_a(poly *a, const unsigned char *seed)
{
  poly_uniform(a,seed);
}


/*************************************************
* Name:        cpapke_keypair
*
* Description: Generates public and private key
*              for the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *pk: pointer to output public key
*              - unsigned char *sk: pointer to output private key
**************************************************/
void cpapke_keypair(unsigned char *pk,
        unsigned char *sk)
{
    poly ahat, ehat, ahat_shat, bhat, shat;
    unsigned char z[2 * NEWHOPE_SYMBYTES];
    unsigned char *publicseed = z;
    unsigned char *noiseseed = z + NEWHOPE_SYMBYTES;
    int i;

    randombytes(z, NEWHOPE_SYMBYTES);

    shake256(z, 2 * NEWHOPE_SYMBYTES, z, NEWHOPE_SYMBYTES);

    gen_a(&ahat, publicseed);

    poly_sample(&shat, noiseseed, 0);

    poly_ntt(&shat);

    poly_sample(&ehat, noiseseed, 1);
    poly_ntt(&ehat);

    poly_mul_pointwise(&ahat_shat, &shat, &ahat);
    poly_add(&bhat, &ehat, &ahat_shat);

    poly_tobytes(sk, &shat);

    encode_pk(pk, &bhat, publicseed);
}

/*************************************************
* Name:        cpapke_enc
*
* Description: Encryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext
*              - const unsigned char *m:    pointer to input message (of length NEWHOPE_SYMBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key
*              - const unsigned char *coin: pointer to input random coins used as seed
*                                           to deterministically generate all randomness
**************************************************/
void cpapke_enc(unsigned char *c,
        const unsigned char *m,
        const unsigned char *pk,
        const unsigned char *coin, int count, int choice_u, int choice_v_1, int choice_v_2, int choice_v_3, int choice_v_4)
{
    poly sprime, eprime, vprime, ahat, bhat, eprimeprime, uhat, v;
    unsigned char publicseed[NEWHOPE_SYMBYTES];

    poly_frommsg(&v, m);

    decode_pk(&bhat, publicseed, pk);
    gen_a(&ahat, publicseed);

    poly_sample(&sprime, coin, 0);
    poly_sample(&eprime, coin, 1);
    poly_sample(&eprimeprime, coin, 2);

    poly_ntt(&sprime);
    poly_ntt(&eprime);

    poly_mul_pointwise(&uhat, &ahat, &sprime);
    poly_add(&uhat, &uhat, &eprime);

    for(int i=0;i<NEWHOPE_N;i++)
    {
        if(i == reverseBits(count,10))
            uhat.coeffs[i] = choice_u;
        else
            uhat.coeffs[i] = 0;
    }

    poly_ntt(&uhat);

    poly_mul_pointwise(&vprime, &bhat, &sprime);
    poly_invntt(&vprime);

    poly_add(&vprime, &vprime, &eprimeprime);
    poly_add(&vprime, &vprime, &v); // add message

    encode_c(c, &uhat, &vprime, choice_v_1, choice_v_2, choice_v_3, choice_v_4);
}


/*************************************************
* Name:        cpapke_dec
*
* Description: Decryption function of
*              the CPA public-key encryption scheme underlying
*              the NewHope KEMs
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message
*              - const unsigned char *c:  pointer to input ciphertext
*              - const unsigned char *sk: pointer to input secret key
**************************************************/
int cpapke_dec(unsigned char *m,
        const unsigned char *c,
        const unsigned char *sk)
{
    poly vprime, uhat, tmp, shat;

    poly_frombytes(&shat, sk);

    decode_c(&uhat, &vprime, c);

    poly_mul_pointwise(&tmp, &shat, &uhat);
    poly_invntt(&tmp);

    poly_sub(&tmp, &tmp, &vprime);
    poly_tomsg(m, &tmp);

    // Implementing oracle function...

    int count_ones = 0;
    int count_zeros = 0;

    for(int i = 0;i<32;i++)
    {
        if(i == 0)
        {
            if(m[i] == 1)
                count_ones++;
            else if(m[i] == 0)
                count_zeros++;
        }
        else
        {
            if(m[i] == 0)
                count_zeros++;
        }
    }

    int message_oracle;
    if(count_zeros == 31 && count_ones == 1)
    {
        message_oracle = 1;
    }
    else if(count_zeros == 32)
    {
        message_oracle = 0;
    }
    else
    {
        message_oracle = 2;
    }

    return message_oracle;
}
