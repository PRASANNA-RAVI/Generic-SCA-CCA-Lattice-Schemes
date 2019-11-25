#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "api.h"

/*************************************************
* Name:        coeff_freeze
*
* Description: Fully reduces an integer modulo q in constant time
*
* Arguments:   uint16_t x: input integer to be reduced
*
* Returns integer in {0,...,q-1} congruent to x modulo q
**************************************************/
static uint16_t coeff_freeze(uint16_t x)
{
  uint16_t m,r;
  int16_t c;
  r = x % NEWHOPE_Q;

  m = r - NEWHOPE_Q;
  c = m;
  c >>= 15;
  r = m ^ ((r^m)&c);

  return r;
}

/*************************************************
* Name:        flipabs
*
* Description: Computes |(x mod q) - Q/2|
*
* Arguments:   uint16_t x: input coefficient
*
* Returns |(x mod q) - Q/2|
**************************************************/
static uint16_t flipabs(uint16_t x)
{
  int16_t r,m;
  r = coeff_freeze(x);

  r = r - NEWHOPE_Q/2;
  m = r >> 15;
  return (r + m) ^ m;
}

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
  int choice_v1, choice_v2, choice_v3, choice_v4;
  char c_matrix_file_name[20];

  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);

  int i,j;
  int choice1,choice2,choice3,choice4;
  int choice11, choice21;

  int crypto_kem_dec_success;
  int count_success = 0;
  int analysed_coeff;
  int coeffs_tried = 0;

  int succ_coeff_array[2*(NEWHOPE_K)+1];
  int other_succ_coeff_array[2*(NEWHOPE_K)+1];
  int sum = 0;
  int flag = 0;
  int temp1, temp2, temp3, temp4;

  int no_trials = 0;
  int choice_u_scheme, choice_v_scheme, choice_scheme;

  int MAX_TRIALS = 100;

  int u_choices[MAX_TRIALS];
  int v_choices[MAX_TRIALS];
  uint8_t decrypt_success_matrix[MAX_TRIALS][(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)];

  for(i=0;i<MAX_TRIALS;i++)
  {
      for(j=0;j<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);j++)
      {
          decrypt_success_matrix[i][j] = 0;
      }
  }

  choice_u_scheme = 415;
  choice_v_scheme = 1041;
  // choice_scheme = 0;

  uint32_t float_u;
  uint32_t float_v1, float_v2, float_v3, float_v4;
  uint32_t compressed_v1, compressed_v2, compressed_v3, compressed_v4;
  uint32_t decompressed_v1, decompressed_v2, decompressed_v3, decompressed_v4;
  uint32_t compressed_u, compressed_v;
  uint32_t decompressed_u, decompressed_v;

  uint16_t t;

  char bits_values[30];
  char collision_bits_values[30];
  char u_values[30];
  char v_1_values[30];
  char v_2_values[30];
  char colliding_rows[30];
  char colliding_rows_numbers[30];

  uint32_t choice_2;
  uint32_t print_once = 0;
  int bit_array[(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)];
  int prev_bit_array[(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)];

    FILE *f;
    flag = 1;

    int flag_u = 0;
    int chose_u = 0;

    int no_collected = 0;
    int greatest_sum = 0;
    int MAX_CLASHES=30;
    int max_no_collected =289;

    int collision_rows_dup[max_no_collected][MAX_CLASHES];
    int collision_rows_number_dup[max_no_collected];

    while(flag == 1)
    {
        int flag_all_zeros = 0;
        int flag_all_ones = 0;

        sprintf(bits_values,"bits_values.dat");
        FILE * f1 = fopen(bits_values, "w+");
        fclose(f1);

        sprintf(u_values,"u_values.dat");
        FILE * f2 = fopen(u_values, "w+");
        fclose(f2);

        sprintf(v_1_values,"v_1_values.dat");
        FILE * f3 = fopen(v_1_values, "w+");
        fclose(f3);

        sprintf(v_2_values,"v_2_values.dat");
        FILE * f4 = fopen(v_2_values, "w+");
        fclose(f4);

        sprintf(colliding_rows,"colliding_rows.dat");
        FILE * f5 = fopen(colliding_rows, "w+");
        fclose(f5);

        sprintf(colliding_rows_numbers,"colliding_rows_numbers.dat");
        FILE * f6 = fopen(colliding_rows_numbers, "w+");
        fclose(f6);

        flag = 0;
        no_trials = 0;
        while(no_trials < MAX_TRIALS)
        {
            // if(no_trials%10 == 0)
            printf("no_trials: %d\n",no_trials);
            f = fopen("/dev/random", "r");
            fread(&choice_v1, sizeof(choice_v1), 1, f);
            fclose(f);
            choice_v1 = choice_v1%NEWHOPE_Q;
            if(choice_v1 < 0)
                choice_v1 = choice_v1+NEWHOPE_Q;

            f = fopen("/dev/random", "r");
            fread(&choice_v2, sizeof(choice_v2), 1, f);
            fclose(f);
            choice_v2 = choice_v2%NEWHOPE_Q;
            if(choice_v2 < 0)
                choice_v2 = choice_v2+NEWHOPE_Q;

            float_v1 = coeff_freeze(choice_v1);
            float_v1 = (((float_v1 << 3) + NEWHOPE_Q/2)/NEWHOPE_Q) & 0x7;
            decompressed_v1 = ((uint32_t)float_v1 * NEWHOPE_Q + 4) >> 3;

            float_v2 = coeff_freeze(choice_v2);
            float_v2 = (((float_v2 << 3) + NEWHOPE_Q/2)/NEWHOPE_Q) & 0x7;
            decompressed_v2 = ((uint32_t)float_v2 * NEWHOPE_Q + 4) >> 3;

            chose_u = 0;

            while(chose_u == 0)
            {
                flag_u = 0;
                f = fopen("/dev/random", "r");
                fread(&choice_u, sizeof(choice_u), 1, f);
                fclose(f);
                choice_u = choice_u%NEWHOPE_Q;
                if(choice_u < 0)
                    choice_u = choice_u+NEWHOPE_Q;

                for(choice11 = -1*(NEWHOPE_K);choice11<=(NEWHOPE_K);choice11++)
                {
                    for(choice21 = -1*(NEWHOPE_K);choice21<=(NEWHOPE_K);choice21++)
                    {
                        temp1 = ((choice_u*choice11) + 3*NEWHOPE_Q) % NEWHOPE_Q;
                        if(temp1 < 0)
                            temp1 = temp1 + NEWHOPE_Q;

                        temp2 = ((choice_u*choice21) + 3*NEWHOPE_Q) % NEWHOPE_Q;
                        if(temp2 < 0)
                            temp2 = temp2 + NEWHOPE_Q;

                        // temp3 = ((choice_u*choice3) + 3*NEWHOPE_Q - decompressed_v3) % NEWHOPE_Q;
                        // if(temp3 < 0)
                        //     temp3 = temp3 + NEWHOPE_Q;
                        //
                        // temp4 = ((choice_u*choice4) + 3*NEWHOPE_Q - decompressed_v4) % NEWHOPE_Q;
                        // if(temp4 < 0)
                        //     temp4 = temp4 + NEWHOPE_Q;
                        // printf("us....\n");
                        // printf("temp1 = %d, temp2 = %d\n",temp1,temp2);
                        t  = flipabs(temp1);
                        t += flipabs(temp2);
                        // t += flipabs(temp3);
                        // t += flipabs(temp4);
                        t = t - (NEWHOPE_Q/2);
                        // t = ((t - NEWHOPE_Q));
                        t >>= 15;
                        bit_array[(choice21+(NEWHOPE_K))+(choice11+(NEWHOPE_K))*(2*NEWHOPE_K+1)] = t;
                        if(t == 1)
                            flag_u = 1;
                    }
                }

                if(flag_u == 0)
                {
                    chose_u = 1;
                }
            }

            for(choice1 = -1*(NEWHOPE_K);choice1<=(NEWHOPE_K);choice1++)
            {
                for(choice2 = -1*(NEWHOPE_K);choice2<=(NEWHOPE_K);choice2++)
                {
                    // printf("choice1 = %d, choice2 = %d\n",choice1,choice2);
                    // for(choice3 = -1*(NEWHOPE_K);choice3<=(NEWHOPE_K);choice3++)
                    // {
                    //     for(choice4 = -1*(NEWHOPE_K);choice4<=(NEWHOPE_K);choice4++)
                    //     {

                                temp1 = (((choice_u*choice1) % NEWHOPE_Q) + 3*NEWHOPE_Q - decompressed_v1) % NEWHOPE_Q;
                                if(temp1 < 0)
                                    temp1 = temp1 + NEWHOPE_Q;

                                temp2 = (((choice_u*choice2) % NEWHOPE_Q) + 3*NEWHOPE_Q - decompressed_v2) % NEWHOPE_Q;
                                if(temp2 < 0)
                                    temp2 = temp2 + NEWHOPE_Q;

                                temp3 = (((choice_u*choice3) % NEWHOPE_Q) + 3*NEWHOPE_Q - decompressed_v3) % NEWHOPE_Q;
                                if(temp3 < 0)
                                    temp3 = temp3 + NEWHOPE_Q;

                                temp4 = (((choice_u*choice4) % NEWHOPE_Q) + 3*NEWHOPE_Q - decompressed_v4) % NEWHOPE_Q;
                                if(temp4 < 0)
                                    temp4 = temp4 + NEWHOPE_Q;

                                t  = flipabs(temp1);
                                t += flipabs(temp2);
                                // t += flipabs(temp3);
                                // t += flipabs(temp4);
                                t = t - (NEWHOPE_Q/2);
                                // t = ((t - NEWHOPE_Q));

                                t >>= 15;
                                decrypt_success_matrix[no_trials][((choice2+(NEWHOPE_K)))+((choice1+(NEWHOPE_K))*(2*NEWHOPE_K+1))] = t;
                    //     }
                    // }
                }
            }

            // Check if array is all zeros or all ones...
            int count_ones = 0;
            int count_zeros = 0;
            for(int oo=0;oo<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);oo++)
            {
                if(decrypt_success_matrix[no_trials][oo] == 0)
                    count_zeros++;
                else
                    count_ones++;
            }

            if(count_zeros == (2*NEWHOPE_K+1)*(2*NEWHOPE_K+1))
            {
                if(flag_all_zeros == 0)
                    flag_all_zeros = 1;
                else if(flag_all_zeros == 1)
                {
                    printf("Found all zero row...\n");
                    continue;
                }
            }

            if(count_ones == (2*NEWHOPE_K+1)*(2*NEWHOPE_K+1))
            {
                if(flag_all_ones == 0)
                    flag_all_ones = 1;
                else if(flag_all_ones == 1)
                {
                    printf("Found all ones row...\n");
                    continue;
                }
            }

            // Check if row is unique, only then add else do not add...

            int flag_same = 0;
            if(no_trials >= 1)
            {
                for(int oo=0;oo<no_trials;oo++)
                {
                    int count_same_2 = 0;
                    for(int pp=0;pp<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);pp++)
                    {
                        if(decrypt_success_matrix[oo][pp] == decrypt_success_matrix[no_trials][pp])
                        {
                            count_same_2 = count_same_2+1;
                        }
                        if(count_same_2 == (2*NEWHOPE_K+1)*(2*NEWHOPE_K+1))
                        {
                            flag_same = 1;
                            printf("Found same row...\n");
                            // continue;
                        }
                    }
                }
            }

            if(flag_same == 1)
                continue;

            FILE * f1 = fopen(u_values, "a");
            fprintf(f1,"%d, ",choice_u);
            fclose(f1);

            FILE * f2 = fopen(v_1_values, "a");
            fprintf(f2,"%d, ",choice_v1);
            fclose(f2);

            FILE * f3 = fopen(v_2_values, "a");
            fprintf(f3,"%d, ",choice_v2);
            fclose(f3);

            FILE * f4 = fopen(bits_values, "a");
            for(int pp=0;pp<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);pp++)
                fprintf(f4,"%d, ", decrypt_success_matrix[no_trials][pp]);
            fprintf(f4,"\n");
            fclose(f4);

            no_trials = no_trials+1;
        }

        // Got the samples and now testing...

        int col_1 = 0;
        int col_2 = 0;
        int element = 0;
        int same_element_row_count = 0;
        int total_matches = 0;

        // Counting number of unique rows in decrypt_success_matrix...

        // Now, I am trying to print out which rows are actually the same...

        int current_row[MAX_TRIALS];
        int flag_went_into_no_collected = 0;

        int unique_rows_collection[(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)][MAX_TRIALS];
        no_collected = 0;

        for(col_1 = 0; col_1<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1) ; col_1++)
        {
            for(col_2 = 0; col_2<MAX_TRIALS ; col_2++)
            {
                current_row[col_2] = decrypt_success_matrix[col_2][col_1];
            }

            if(no_collected == 0)
            {
                for(int uu=0;uu<MAX_TRIALS;uu++)
                    unique_rows_collection[0][uu] = current_row[uu];
                flag_went_into_no_collected = 1;
            }
            else
            {
                int same_row_found_flag = 0;
                for(int yy=0;yy<no_collected;yy++)
                {
                    int same_sum = 0;
                    for(int zz=0;zz<MAX_TRIALS;zz++)
                    {
                        if(unique_rows_collection[yy][zz] == current_row[zz])
                            same_sum++;
                    }
                    if(same_sum == MAX_TRIALS)
                    {
                        same_row_found_flag = 1;
                        // Found same row...
                        break;
                    }
                }
                if(same_row_found_flag == 0)
                {
                    // If found new row, then add it to the unique collection...
                    for(int yy=0;yy<MAX_TRIALS;yy++)
                        unique_rows_collection[no_collected][yy] = current_row[yy];
                    no_collected = no_collected+1;
                }
            }

            if(flag_went_into_no_collected == 1)
            {
                no_collected = no_collected+1;
                flag_went_into_no_collected = 0;
            }
        }

        printf("no_collected: %d\n",no_collected);

        int collision_rows[no_collected][MAX_CLASHES];
        int collision_rows_number[no_collected];

        for(int yy=0;yy<no_collected;yy++)
        {
            for(int zz=0;zz<MAX_CLASHES;zz++)
            {
                collision_rows[yy][zz] = 0;
            }
        }

        for(col_1 = 0;col_1<no_collected;col_1++)
        {
            int sum = 0;
            for(col_2 = 0;col_2<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);col_2++)
            {
                int same_sum = 0;
                for(int col_3 = 0;col_3<MAX_TRIALS;col_3++)
                {
                    if(unique_rows_collection[col_1][col_3] == decrypt_success_matrix[col_3][col_2])
                        same_sum++;
                }
                if(same_sum == MAX_TRIALS)
                {
                    collision_rows[col_1][sum] = col_2;
                    sum++;
                }
            }
            collision_rows_number[col_1] = sum;
        }

        f5 = fopen(colliding_rows, "a");
        for(int yy=0;yy<no_collected;yy++)
        {
            for(int zz=0;zz<collision_rows_number[yy];zz++)
            {
                fprintf(f5,"%d, ", collision_rows[yy][zz]);
                collision_rows_dup[yy][zz] = collision_rows[yy][zz];
            }
            fprintf(f5,"\n");
        }
        fclose(f5);

        f6 = fopen(colliding_rows_numbers, "a");
        for(int yy=0;yy<no_collected;yy++)
        {
            fprintf(f6,"%d, ", collision_rows_number[yy]);
            collision_rows_number_dup[yy] = collision_rows_number[yy];
        }
        fclose(f6);

        greatest_sum = 0;

        for(int yy=0;yy<no_collected;yy++)
        {
            if(collision_rows_number[yy] > greatest_sum)
                greatest_sum = collision_rows_number[yy];
        }

        printf("Max Clashes:%d\n",greatest_sum);

        // if(greatest_sum >= 5)
        //     flag = 1;
    }

    // Now I have come out...I have narrowed down the search space, considerably for each coefficient combo...I
    // now just have to find unique solution for every coefficient within the smaller search space. For which, it looks
    // like i will have to repeat the process again...

    int current_conflicted_rows[greatest_sum];

    sprintf(collision_bits_values,"collision_bits_values.dat");
    FILE * f1 = fopen(collision_bits_values, "w+");
    fclose(f1);

    for(int row_no=0;row_no<no_collected;row_no++)
    {
        int no_conflicted = collision_rows_number_dup[row_no];
        int current_conflicted_pair_rows[2];

        if(no_conflicted == 1)
        {
            printf("Skipping row no: %d\n",row_no);
            continue;
        }
        if(no_conflicted > 1) // Processing between pairs...
        {
            printf("Processing row no: %d\n",row_no);
            double trials = 1;
            int MAX_TRIALS = 1;
            for(int yy=0;yy<no_conflicted;yy++)
                current_conflicted_rows[yy] = collision_rows_dup[row_no][yy];

            int comb_no = 0;
            for(int tt = 0;tt<no_conflicted;tt++)
            {
                for(int qq = tt+1;qq<no_conflicted;qq++)
                {
                    printf("Processing comb no: %d\n",comb_no);
                    comb_no++;
                    current_conflicted_pair_rows[0] = current_conflicted_rows[tt];
                    current_conflicted_pair_rows[1] = current_conflicted_rows[qq];

                    int rep_flag = 1;
                    while(rep_flag == 1)
                    {
                        no_trials = 0;
                        while(no_trials < MAX_TRIALS)
                        {
                            f = fopen("/dev/random", "r");
                            fread(&choice_v1, sizeof(choice_v1), 1, f);
                            fclose(f);
                            choice_v1 = choice_v1%NEWHOPE_Q;
                            if(choice_v1 < 0)
                                choice_v1 = choice_v1+NEWHOPE_Q;

                            f = fopen("/dev/random", "r");
                            fread(&choice_v2, sizeof(choice_v2), 1, f);
                            fclose(f);
                            choice_v2 = choice_v2%NEWHOPE_Q;
                            if(choice_v2 < 0)
                                choice_v2 = choice_v2+NEWHOPE_Q;

                            // f = fopen("/dev/random", "r");
                            // fread(&choice_v3, sizeof(choice_v3), 1, f);
                            // fclose(f);
                            // choice_v3 = choice_v3%NEWHOPE_Q;
                            // if(choice_v3 < 0)
                            //     choice_v3 = choice_v3+NEWHOPE_Q;
                            //
                            // f = fopen("/dev/random", "r");
                            // fread(&choice_v4, sizeof(choice_v4), 1, f);
                            // fclose(f);
                            // choice_v4 = choice_v4%NEWHOPE_Q;
                            // if(choice_v4 < 0)
                            //     choice_v4 = choice_v4+NEWHOPE_Q;

                            float_v1 = coeff_freeze(choice_v1);
                            float_v1 = (((float_v1 << 3) + NEWHOPE_Q/2)/NEWHOPE_Q) & 0x7;
                            decompressed_v1 = ((uint32_t)float_v1 * NEWHOPE_Q + 4) >> 3;

                            float_v2 = coeff_freeze(choice_v2);
                            float_v2 = (((float_v2 << 3) + NEWHOPE_Q/2)/NEWHOPE_Q) & 0x7;
                            decompressed_v2 = ((uint32_t)float_v2 * NEWHOPE_Q + 4) >> 3;

                            // float_v3 = coeff_freeze(choice_v3);
                            // float_v3 = (((float_v3 << 3) + NEWHOPE_Q/2)/NEWHOPE_Q) & 0x7;
                            // decompressed_v3 = ((uint32_t)float_v3 * NEWHOPE_Q + 4) >> 3;
                            //
                            // float_v4 = coeff_freeze(choice_v4);
                            // float_v4 = (((float_v4 << 3) + NEWHOPE_Q/2)/NEWHOPE_Q) & 0x7;
                            // decompressed_v4 = ((uint32_t)float_v4 * NEWHOPE_Q + 4) >> 3;

                            // Choosing U......

                            chose_u = 0;

                            while(chose_u == 0)
                            {
                                flag_u = 0;
                                f = fopen("/dev/random", "r");
                                fread(&choice_u, sizeof(choice_u), 1, f);
                                fclose(f);
                                choice_u = choice_u%NEWHOPE_Q;
                                if(choice_u < 0)
                                    choice_u = choice_u+NEWHOPE_Q;

                                for(choice11 = -1*(NEWHOPE_K);choice11<=(NEWHOPE_K);choice11++)
                                {
                                    for(choice21 = -1*(NEWHOPE_K);choice21<=(NEWHOPE_K);choice21++)
                                    {
                                        temp1 = ((choice_u*choice11) + 3*NEWHOPE_Q) % NEWHOPE_Q;
                                        if(temp1 < 0)
                                            temp1 = temp1 + NEWHOPE_Q;

                                        temp2 = ((choice_u*choice21) + 3*NEWHOPE_Q) % NEWHOPE_Q;
                                        if(temp2 < 0)
                                            temp2 = temp2 + NEWHOPE_Q;

                                        // temp3 = ((choice_u*choice3) + 3*NEWHOPE_Q - decompressed_v3) % NEWHOPE_Q;
                                        // if(temp3 < 0)
                                        //     temp3 = temp3 + NEWHOPE_Q;
                                        //
                                        // temp4 = ((choice_u*choice4) + 3*NEWHOPE_Q - decompressed_v4) % NEWHOPE_Q;
                                        // if(temp4 < 0)
                                        //     temp4 = temp4 + NEWHOPE_Q;

                                        t  = flipabs(temp1);
                                        t += flipabs(temp2);
                                        // t += flipabs(temp3);
                                        // t += flipabs(temp4);
                                        t = t - (NEWHOPE_Q/2);
                                        // t = ((t - NEWHOPE_Q));
                                        t >>= 15;
                                        bit_array[(choice21+(NEWHOPE_K))+(choice11+(NEWHOPE_K))*(2*NEWHOPE_K+1)] = t;
                                        if(t == 1)
                                            flag_u = 1;
                                    }
                                }

                                if(flag_u == 0)
                                {
                                    chose_u = 1;
                                }
                            }

                            for(int iii=0;iii<2;iii++)
                            {
                                choice1 = ((int)current_conflicted_pair_rows[iii]/(2*NEWHOPE_K+1)) - NEWHOPE_K;
                                choice2 = ((int)current_conflicted_pair_rows[iii]%(2*NEWHOPE_K+1)) - NEWHOPE_K;

                                temp1 = (((choice_u*choice1) % NEWHOPE_Q) + 3*NEWHOPE_Q - decompressed_v1) % NEWHOPE_Q;
                                if(temp1 < 0)
                                    temp1 = temp1 + NEWHOPE_Q;

                                temp2 = (((choice_u*choice2) % NEWHOPE_Q) + 3*NEWHOPE_Q - decompressed_v2) % NEWHOPE_Q;
                                if(temp2 < 0)
                                    temp2 = temp2 + NEWHOPE_Q;

                                t  = flipabs(temp1);
                                t += flipabs(temp2);
                                // t += flipabs(temp3);
                                // t += flipabs(temp4);
                                t = t - (NEWHOPE_Q/2);
                                // t = ((t - NEWHOPE_Q));

                                t >>= 15;

                                decrypt_success_matrix[no_trials][iii] = t;
                            }
                            no_trials = no_trials+1;
                        }

                        int col_1 = 0;
                        int col_2 = 0;
                        int element = 0;
                        int same_element_row_count = 0;
                        int total_matches = 0;

                        // Counting number of unique rows in decrypt_success_matrix...

                        int no_collected = 0;
                        int unique_rows_collection[2][1];

                        int current_row[1];
                        int flag_went_into_no_collected = 0;

                        for(col_1 = 0; col_1<2 ; col_1++)
                        {
                            for(col_2 = 0; col_2<1 ; col_2++)
                            {
                                current_row[col_2] = decrypt_success_matrix[col_2][col_1];
                            }

                            if(no_collected == 0)
                            {
                                for(int uu=0;uu<1;uu++)
                                    unique_rows_collection[0][uu] = current_row[uu];
                                flag_went_into_no_collected = 1;
                            }
                            else
                            {
                                int same_row_found_flag = 0;
                                for(int yy=0;yy<no_collected;yy++)
                                {
                                    int same_sum = 0;
                                    for(int zz=0;zz<MAX_TRIALS;zz++)
                                    {
                                        if(unique_rows_collection[yy][zz] == current_row[zz])
                                            same_sum++;
                                    }
                                    if(same_sum == MAX_TRIALS)
                                    {
                                        same_row_found_flag = 1;
                                        // Found same row...
                                        break;
                                    }
                                }
                                if(same_row_found_flag == 0)
                                {
                                    // If found new row, then add it to the unique collection...
                                    for(int yy=0;yy<MAX_TRIALS;yy++)
                                        unique_rows_collection[no_collected][yy] = current_row[yy];
                                    no_collected = no_collected+1;
                                }
                            }

                            if(flag_went_into_no_collected == 1)
                            {
                                no_collected = no_collected+1;
                                flag_went_into_no_collected = 0;
                            }
                        }

                        if(no_collected == 2)
                        {
                            rep_flag = 0;

                            FILE * f1 = fopen(u_values, "a");
                            fprintf(f1,"%d, ",choice_u);
                            fclose(f1);

                            FILE * f2 = fopen(v_1_values, "a");
                            fprintf(f2,"%d, ",choice_v1);
                            fclose(f2);

                            FILE * f3 = fopen(v_2_values, "a");
                            fprintf(f3,"%d, ",choice_v2);
                            fclose(f3);

                            FILE * f4 = fopen(collision_bits_values, "a");
                            for(col_1 = 0; col_1<2 ; col_1++)
                            {
                                for(col_2 = 0; col_2<1 ; col_2++)
                                {
                                    fprintf(f4,"%d, ", decrypt_success_matrix[col_2][col_1]);
                                }
                                fprintf(f4,"\n");
                            }
                            fclose(f4);

                            printf("Resolved...\n");
                        }
                        else
                        {
                            // printf("Not Resolved...\n");
                        }
                    }
                }
            }
        }
    }
  return 0;
}
