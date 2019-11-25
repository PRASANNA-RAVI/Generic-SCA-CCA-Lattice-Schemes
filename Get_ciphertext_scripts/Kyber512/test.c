#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <math.h>
#include "api.h"

#define NTESTS 1

static void write_canary(unsigned char *d)
{
  *((uint64_t *) d)= 0x0123456789ABCDEF;
}

static int check_canary(unsigned char *d)
{
  if(*(uint64_t *) d !=  0x0123456789ABCDEF)
    return -1;
  else
    return 0;
}

int main(void)
{

  unsigned char key_a[CRYPTO_BYTES+16], key_b[CRYPTO_BYTES+16];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char sk_a[CRYPTO_SECRETKEYBYTES+16];

  int choice_u, choice_v;

  char c_matrix_file_name[20];

  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);

  int i;
  int choice;
  int crypto_kem_dec_success;
  int count_success = 0;
  int analysed_coeff;
  int coeffs_tried = 0;
  int16_t temp_1, temp_2;
  uint16_t bit_1, bit_2;
  int succ_coeff_array[2*KYBER_ETA+1];
  int other_succ_coeff_array[2*KYBER_ETA+1];
  int sum = 0;
  int flag = 0;

  int choice_u_scheme, choice_v_scheme, choice_scheme;
  int sum_other_coeff_array = 0;

  uint8_t decrypt_success_array[2*KYBER_ETA+1];

  double float_u, float_v;
  int compressed_u, compressed_v;
  int decompressed_u, decompressed_v;

  int choice_2;
  int print_once = 0;

  for(i=0;i<2*KYBER_ETA+1;i++)
    succ_coeff_array[i] = 0;

    for(choice_u = 0; choice_u<KYBER_Q; choice_u++)
    {
        for(choice_v = 0; choice_v<KYBER_Q; choice_v++)
        {
            sum = 0;
            for(i=0;i<2*KYBER_ETA+1;i++)
            {
                sum += succ_coeff_array[i];
            }

            if(sum == 2*KYBER_ETA+1)
            {
                flag = 1;
                break;
            }

            for(int ii=0;ii<2*KYBER_ETA+1;ii++)
                decrypt_success_array[ii] = 0;

            for(choice = -1*KYBER_ETA;choice<=KYBER_ETA;choice++)
            {

                float_u = ((double)1024/KYBER_Q)*choice_u;
                compressed_u = (int)round(float_u) % 1024;

                float_u = ((double)KYBER_Q/1024)*compressed_u;
                decompressed_u = round(float_u);

                // printf("%d, %d, %d\n",choice_u,compressed_u,decompressed_u);

                float_v = ((double)8/KYBER_Q)*choice_v;
                compressed_v = (int)round(float_v) % 8;

                float_v = ((double)KYBER_Q/8)*compressed_v;
                decompressed_v = round(float_v);

                temp_1 = (decompressed_v - (decompressed_u*choice))%KYBER_Q;
                if(temp_1 < 0)
                    temp_1 = temp_1 + KYBER_Q;

                temp_1 = csubq(temp_1);
                bit_1 = (((temp_1 << 1) + KYBER_Q/2) / KYBER_Q) & 1;

                for(int ii=0;ii<2*KYBER_ETA+1;ii++)
                    other_succ_coeff_array[ii] = 0;

                for(choice_2 = -1*KYBER_ETA;choice_2 <= KYBER_ETA;choice_2++)
                {
                    float_v = ((double)8/KYBER_Q)*0; // choice_v = 0
                    compressed_v = (int)round(float_v) % 8;

                    float_v = ((double)KYBER_Q/8)*compressed_v;
                    decompressed_v = round(float_v);

                    temp_2 = (decompressed_v - (decompressed_u*choice_2))%KYBER_Q;
                    if(temp_2 < 0)
                        temp_2 = temp_2 + KYBER_Q;

                    temp_2 = csubq(temp_2);
                    bit_2 = (((temp_2 << 1) + KYBER_Q/2) / KYBER_Q) & 1;

                    other_succ_coeff_array[choice_2+KYBER_ETA] = bit_2;
                }

                sum_other_coeff_array = 0;
                for(int ii = 0;ii<2*KYBER_ETA+1;ii++)
                {
                    sum_other_coeff_array+=other_succ_coeff_array[ii];
                }

                if((bit_1 == 1 && sum_other_coeff_array == 0) || (bit_1 == 0 && sum_other_coeff_array == 2*KYBER_ETA+1))
                {
                    decrypt_success_array[choice+KYBER_ETA] = 1;
                }
                else
                {
                    decrypt_success_array[choice+KYBER_ETA] = 0;
                }
            }

            if(sum_other_coeff_array == 0)
            {
                float_v = ((double)8/KYBER_Q)*choice_v; // choice_v = 0
                compressed_v = (int)round(float_v) % 8;

                printf("Choice_u, Choice_v: %d, %d\n",choice_u, compressed_v);
                for(int i=0;i<2*KYBER_ETA+1;i++)
                    printf("%d, ",decrypt_success_array[i]);
                printf("\n");
            }

            count_success = 0;
            for(choice = 0;choice<2*KYBER_ETA+1;choice++)
            {
                count_success+=decrypt_success_array[choice];
                if(decrypt_success_array[choice] == 1)
                    analysed_coeff = choice-KYBER_ETA;
            }
        }
    }

  return 0;
}
