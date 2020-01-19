#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "rng.h"
#include "api.h"
#include "ntt.h"
#include "poly.h"
#include "reduce.h"
#include "rng.h"
#include "verify.h"
#include "fips202.h"

// You can run the program with the following options:

// generate_first_cts
// compute_complexity
// resolve_conflicts
// run_attacks <NUMBER OF ATTACKS IN INTEGER>

void cats(char **str, const char *str2) {
    char *tmp = NULL;

    // Reset *str
    if ( *str != NULL && str2 == NULL ) {
        free(*str);
        *str = NULL;
        return;
    }

    // Initial copy
    if (*str == NULL) {
        *str = calloc( strlen(str2)+1, sizeof(char) );
        memcpy( *str, str2, strlen(str2) );
    }
    else { // Append
        tmp = calloc( strlen(*str)+1, sizeof(char) );
        memcpy( tmp, *str, strlen(*str) );
        *str = calloc( strlen(*str)+strlen(str2)+1, sizeof(char) );
        memcpy( *str, tmp, strlen(tmp) );
        memcpy( *str + strlen(*str), str2, strlen(str2) );
        free(tmp);
    }

} // cats


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

int main(int argc, char *argv[])
{

    // Seed different randomness...

    unsigned char       seed[48];
    unsigned char       entropy_input[48];

    randombytes_init(entropy_input, NULL, 256);
    for (int i=0; i<100; i++)
    {
        randombytes(seed, 48);
    }
    randombytes_init(seed, NULL, 256);

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
  int choice11, choice21, choice31, choice41;

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

  // Initial number of random ciphertexts we try to get as many uniquely identifiable candidates as possible...

  int MAX_TRIALS = 100;

  int u_choices[MAX_TRIALS];
  int v_choices[MAX_TRIALS];

  // This is the matrix that stores the oracle's responses for all possible secret candidates and for every chosen ciphertext...

  uint32_t **decrypt_success_matrix = (uint32_t **)malloc(MAX_TRIALS * sizeof(uint32_t*));

  #define no_words_all_secrets (int)((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)/32)+1
  #define last_word_all_secrets (int)((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)%32)

  for(int i = 0; i < MAX_TRIALS; i++)
  {
    decrypt_success_matrix[i] = (uint32_t *)malloc(no_words_all_secrets * sizeof(uint32_t));
  }

  #define no_words_all_trials ((int)(MAX_TRIALS/32)+1)
  #define last_word_all_trials MAX_TRIALS%32

  // Transpose of decrypt_success_matrix...

  uint32_t **trans_decrypt_success_matrix = (uint32_t **)malloc(no_words_all_trials * sizeof(uint32_t*));

  for(int i = 0; i < no_words_all_trials; i++)
  {
    trans_decrypt_success_matrix[i] = (uint32_t *)malloc((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1) * sizeof(uint32_t));
  }

  // This is a maximum limit on the number of conflicts between the different secret candidates.. (i.e) 300 among the 83521 candidates have the same sequence for the
  // chosen ciphertexts.... 300 is much larger compared to the actual number of conflicted candidates in a cluster...

  int MAX_CLASHES=300;

  for(i=0;i<MAX_TRIALS;i++)
  {
      for(j=0;j<no_words_all_secrets;j++)
      {
          decrypt_success_matrix[i][j] = 0;
      }
  }

  uint32_t float_u;
  uint32_t float_v1, float_v2, float_v3, float_v4;
  uint32_t compressed_v1, compressed_v2, compressed_v3, compressed_v4;
  uint32_t decompressed_v1, decompressed_v2, decompressed_v3, decompressed_v4;
  uint32_t compressed_u, compressed_v;
  uint32_t decompressed_u, decompressed_v;

  uint16_t t;

  char bits_values[30], bits_values_resolved[30];
  char trans_bits_values[30];
  char collision_bits_values[30];
  char u_values[30], u_values_resolved[30];
  char v_1_values[30], v_1_values_resolved[30];
  char v_2_values[30], v_2_values_resolved[30];
  char v_3_values[30], v_3_values_resolved[30];
  char v_4_values[30], v_4_values_resolved[30];
  char colliding_rows[30];
  char colliding_rows_numbers[30];
  char greatest_sum_no_collected[30];
  char trans_bits_values_new[30];

  uint32_t choice_2;
  uint32_t print_once = 0;
  int bit_array[(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)];
  int prev_bit_array[(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)];

  #define no_chosen_u 767

  // The ciphertext component u is chosen as a constant u = u0 . x^0

  // This is the list of chosen values for k such that the product u0 times s results in the lsb of message always equal to zero (ignoring v)... So, the chosen values of u for our attack can only have coefficient within
  // these chosen values...

  int chosen_u[no_chosen_u] =  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 11906, 11907, 11908, 11909, 11910, 11911, 11912, 11913, 11914, 11915, 11916, 11917, 11918, 11919, 11920, 11921, 11922, 11923, 11924, 11925, 11926, 11927, 11928, 11929, 11930, 11931, 11932, 11933, 11934, 11935, 11936, 11937, 11938, 11939, 11940, 11941, 11942, 11943, 11944, 11945, 11946, 11947, 11948, 11949, 11950, 11951, 11952, 11953, 11954, 11955, 11956, 11957, 11958, 11959, 11960, 11961, 11962, 11963, 11964, 11965, 11966, 11967, 11968, 11969, 11970, 11971, 11972, 11973, 11974, 11975, 11976, 11977, 11978, 11979, 11980, 11981, 11982, 11983, 11984, 11985, 11986, 11987, 11988, 11989, 11990, 11991, 11992, 11993, 11994, 11995, 11996, 11997, 11998, 11999, 12000, 12001, 12002, 12003, 12004, 12005, 12006, 12007, 12008, 12009, 12010, 12011, 12012, 12013, 12014, 12015, 12016, 12017, 12018, 12019, 12020, 12021, 12022, 12023, 12024, 12025, 12026, 12027, 12028, 12029, 12030, 12031, 12032, 12033, 12034, 12035, 12036, 12037, 12038, 12039, 12040, 12041, 12042, 12043, 12044, 12045, 12046, 12047, 12048, 12049, 12050, 12051, 12052, 12053, 12054, 12055, 12056, 12057, 12058, 12059, 12060, 12061, 12062, 12063, 12064, 12065, 12066, 12067, 12068, 12069, 12070, 12071, 12072, 12073, 12074, 12075, 12076, 12077, 12078, 12079, 12080, 12081, 12082, 12083, 12084, 12085, 12086, 12087, 12088, 12089, 12090, 12091, 12092, 12093, 12094, 12095, 12096, 12097, 12098, 12099, 12100, 12101, 12102, 12103, 12104, 12105, 12106, 12107, 12108, 12109, 12110, 12111, 12112, 12113, 12114, 12115, 12116, 12117, 12118, 12119, 12120, 12121, 12122, 12123, 12124, 12125, 12126, 12127, 12128, 12129, 12130, 12131, 12132, 12133, 12134, 12135, 12136, 12137, 12138, 12139, 12140, 12141, 12142, 12143, 12144, 12145, 12146, 12147, 12148, 12149, 12150, 12151, 12152, 12153, 12154, 12155, 12156, 12157, 12158, 12159, 12160, 12161, 12162, 12163, 12164, 12165, 12166, 12167, 12168, 12169, 12170, 12171, 12172, 12173, 12174, 12175, 12176, 12177, 12178, 12179, 12180, 12181, 12182, 12183, 12184, 12185, 12186, 12187, 12188, 12189, 12190, 12191, 12192, 12193, 12194, 12195, 12196, 12197, 12198, 12199, 12200, 12201, 12202, 12203, 12204, 12205, 12206, 12207, 12208, 12209, 12210, 12211, 12212, 12213, 12214, 12215, 12216, 12217, 12218, 12219, 12220, 12221, 12222, 12223, 12224, 12225, 12226, 12227, 12228, 12229, 12230, 12231, 12232, 12233, 12234, 12235, 12236, 12237, 12238, 12239, 12240, 12241, 12242, 12243, 12244, 12245, 12246, 12247, 12248, 12249, 12250, 12251, 12252, 12253, 12254, 12255, 12256, 12257, 12258, 12259, 12260, 12261, 12262, 12263, 12264, 12265, 12266, 12267, 12268, 12269, 12270, 12271, 12272, 12273, 12274, 12275, 12276, 12277, 12278, 12279, 12280, 12281, 12282, 12283, 12284, 12285, 12286, 12287, 12288};

  // This is the list of all possible values for the coefficients of v... because each coefficient of v is only three bits...

  int chosen_v[8] = {0, 1536, 3072, 4608, 6145, 7681, 9217, 10753};

  // Here, we are calculating the probability of every possible candidate tuple (s0, s1, s2, s3)...

  float probabilities[2*NEWHOPE_K+1];

  for(int kkk = 0;kkk<2*NEWHOPE_K+1;kkk++)
    probabilities[kkk] = 0;

  for(int kkk = 0;kkk<65536;kkk++)
  {
      int sum_prob = 0;
      for(int lll = 0;lll<8;lll++)
      {
        sum_prob = sum_prob + (((kkk>>(2*lll))&0x1) - ((kkk>>(2*lll+1))&0x1));
      }
      probabilities[sum_prob+NEWHOPE_K] = probabilities[sum_prob+NEWHOPE_K]+1;
  }

  for(int kkk = 0;kkk<2*NEWHOPE_K+1;kkk++)
  {
    probabilities[kkk] = (float)probabilities[kkk]/65536;
  }

    int no_collected = 0;
    int greatest_sum = 0;

    // Here, we simply generate "MAX_TRIALS" number of random ciphertexts to uniquely identify as many candidate tuples as possible...

    if(strcmp(argv[1],"generate_first_cts") == 0)
    {

    FILE *f;
    flag = 1;

    int flag_u = 0;
    int chose_u = 0;

    int flag_all_zeros = 0;
    int flag_all_ones = 0;

    sprintf(bits_values,"bits_values.dat");
    FILE * f1 = fopen(bits_values, "w+");
    fclose(f1);

    sprintf(trans_bits_values,"trans_bits_values.dat");
    FILE * f_trans_bits_values = fopen(trans_bits_values, "w+");
    fclose(f_trans_bits_values);

    sprintf(u_values,"u_values.dat");
    FILE * f2 = fopen(u_values, "w+");
    fclose(f2);

    sprintf(v_1_values,"v_1_values.dat");
    FILE * f3 = fopen(v_1_values, "w+");
    fclose(f3);

    sprintf(v_2_values,"v_2_values.dat");
    FILE * f4 = fopen(v_2_values, "w+");
    fclose(f4);

    sprintf(v_3_values,"v_3_values.dat");
    FILE * f5 = fopen(v_3_values, "w+");
    fclose(f5);

    sprintf(v_4_values,"v_4_values.dat");
    FILE * f6 = fopen(v_4_values, "w+");
    fclose(f6);

    sprintf(colliding_rows,"colliding_rows.dat");
    FILE * f7 = fopen(colliding_rows, "w+");
    fclose(f7);

    sprintf(colliding_rows_numbers,"colliding_rows_numbers.dat");
    FILE * f8 = fopen(colliding_rows_numbers, "w+");
    fclose(f8);

    sprintf(greatest_sum_no_collected,"greatest_sum_no_collected.dat");
    FILE * f9 = fopen(greatest_sum_no_collected, "w+");
    fclose(f9);

    no_trials = 0;

    // This loop exits upon collecting N random ciphertexts that can uniquely identify as many tuples as possible... This works by first generating a random ciphertext...
    // We calculate the oracle's response for every possible candidate and if the resulting binary sequence is different from the previously collected sequences, then it is added as a valid ciphertext,
    // if the sequence is all zeros or all ones or is the same as previously a previously collected sequence, then the corresponding ciphertext is rejected....

    while(no_trials < MAX_TRIALS)
    {
        // Four coefficients (v0, v1, v2, v3) for the polynomial v are randomly selected from the chosen_v where v is of the structure
        // v = v0 . x^0 + v1 . x^256 + v2 . x^512 + v3 . x^768... We are also selecting one value for the coefficient of u where u = u0 . x^0

        printf("no_trials: %d\n",no_trials);
        f = fopen("/dev/random", "r");
        fread(&choice_v1, sizeof(choice_v1), 1, f);
        fclose(f);

        choice_v1 = choice_v1&0x7;
        decompressed_v1 = chosen_v[choice_v1];

        f = fopen("/dev/random", "r");
        fread(&choice_v2, sizeof(choice_v2), 1, f);
        fclose(f);

        choice_v2 = choice_v2&0x7;
        decompressed_v2 = chosen_v[choice_v2];

        f = fopen("/dev/random", "r");
        fread(&choice_v3, sizeof(choice_v3), 1, f);
        fclose(f);

        choice_v3 = choice_v3&0x7;
        decompressed_v3 = chosen_v[choice_v3];

        f = fopen("/dev/random", "r");
        fread(&choice_v4, sizeof(choice_v4), 1, f);
        fclose(f);

        choice_v4 = choice_v4&0x7;
        decompressed_v4 = chosen_v[choice_v4];

        uint32_t choicee_u;
        f = fopen("/dev/random", "r");
        fread(&choicee_u, sizeof(choicee_u), 1, f);
        fclose(f);

        choicee_u = choicee_u%(no_chosen_u);
        choice_u = chosen_u[choicee_u];

        // Setting initial values of all entries = 0 in decrypt_success_matrix and trans_decrypt_success_matrix....

        for(int iiii = 0;iiii < no_words_all_secrets; iiii++)
            decrypt_success_matrix[no_trials][iiii] = 0;

        for(choice1 = -1*(NEWHOPE_K);choice1<=(NEWHOPE_K);choice1++)
        {
            for(choice2 = -1*(NEWHOPE_K);choice2<=(NEWHOPE_K);choice2++)
            {
                for(choice3 = -1*(NEWHOPE_K);choice3<=(NEWHOPE_K);choice3++)
                {
                    for(choice4 = -1*(NEWHOPE_K);choice4<=(NEWHOPE_K);choice4++)
                    {
                        int bit_pos = (choice4+(NEWHOPE_K))+(choice3+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(choice2+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(choice1+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);
                        int modulo_word = no_trials%32;
                        int word_pos = (int)(no_trials/32);
                        trans_decrypt_success_matrix[word_pos][bit_pos] = trans_decrypt_success_matrix[word_pos][bit_pos]&(0xFFFFFFFF^(1<<modulo_word));
                    }
                }
            }
        }

        // for every possible candidate tuple (s0, s1, s2, s3), we calculate what will be the corresponding bit of the message based on the chosen values of (u0, v0, v1, v2, v3)...
        // Then we store it in each entry of the decrypt_success_matrix and also in corresponding entry in trans_decrypt_success_matrix...
        // This will fill up one row of 1s and 0s in decrypt_success_matrix and one column in trans_decrypt_success_matrix...

        for(choice1 = -1*(NEWHOPE_K);choice1<=(NEWHOPE_K);choice1++)
        {
            for(choice2 = -1*(NEWHOPE_K);choice2<=(NEWHOPE_K);choice2++)
            {
                for(choice3 = -1*(NEWHOPE_K);choice3<=(NEWHOPE_K);choice3++)
                {
                    for(choice4 = -1*(NEWHOPE_K);choice4<=(NEWHOPE_K);choice4++)
                    {
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
                            t += flipabs(temp3);
                            t += flipabs(temp4);
                            t = ((t - NEWHOPE_Q));

                            t >>= 15;
                            int bit_pos = (choice4+(NEWHOPE_K))+(choice3+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(choice2+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(choice1+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);
                            int modulo_word = bit_pos%32;
                            int word_pos = (int)(bit_pos/32);
                            decrypt_success_matrix[no_trials][word_pos] = decrypt_success_matrix[no_trials][word_pos]|(t<<modulo_word);


                            bit_pos = (choice4+(NEWHOPE_K))+(choice3+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(choice2+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(choice1+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);
                            modulo_word = no_trials%32;
                            word_pos = (int)(no_trials/32);
                            trans_decrypt_success_matrix[word_pos][bit_pos] = trans_decrypt_success_matrix[word_pos][bit_pos]|(t<<modulo_word);
                    }
                }
            }
        }

        // Once we collected one row (resp. column), we need to check if it is simply (1) all one row,
        // or (2) all zero row or (3) row same as previously collected row... Because adding this row is not going to additionally uniquely identify
        // any secret candidate tuple... So, we reject those ciphertexts yielding these values... We only select
        // those ciphertexts that yield different value for the row...

        // Checking if obtained row is all ones or zeros...

        int count_ones = 0;
        int count_zeros = 0;
        for(int oo=0;oo<no_words_all_secrets;oo++)
        {
            if(decrypt_success_matrix[no_trials][oo] == 0)
                count_zeros++;
            else if(decrypt_success_matrix[no_trials][oo] == 0xFFFFFFFF || decrypt_success_matrix[no_trials][no_words_all_secrets-1] == 1)
                count_ones++;
        }

        if(count_zeros == no_words_all_secrets)
        {
                // printf("Found all zero row...\n");  // Restarting the loop for fresh ciphertext...
                continue;
        }

        if(count_ones == no_words_all_secrets)
        {
                // printf("Found all ones row...\n");  // Restarting the loop for fresh ciphertext...
                continue;
        }

        // Checking if obtained row is same as any of the previous rows of decrypt_success_matrix... if so, then reject and try again.... else
        // add it to the list of chosen ciphertexts...

        int flag_same = 0;
        if(no_trials >= 1)
        {
            for(int oo=0;oo<no_trials;oo++)
            {
                uint32_t count_same_2 = 0;
                for(int pp=0;pp<no_words_all_secrets;pp++)
                {
                    count_same_2 = count_same_2 | (decrypt_success_matrix[oo][pp] ^ decrypt_success_matrix[no_trials][pp]);
                }
                if(count_same_2 == 0)
                {
                    flag_same = 1;
                    break;
                }
            }
        }

        if(flag_same == 1) // Restarting the loop for fresh ciphertext...
            continue;

        // Writing the chosen ciphertext values and saving the decrypt_success_matrix row entry to separate text files...

        FILE * f1 = fopen(u_values, "a");
        fprintf(f1,"%d, ",choice_u);
        fprintf(f1,"\n");
        fclose(f1);

        FILE * f2 = fopen(v_1_values, "a");
        fprintf(f2,"%d, ",choice_v1);
        fprintf(f2,"\n");
        fclose(f2);

        FILE * f3 = fopen(v_2_values, "a");
        fprintf(f3,"%d, ",choice_v2);
        fprintf(f3,"\n");
        fclose(f3);

        FILE * f4 = fopen(v_3_values, "a");
        fprintf(f4,"%d, ",choice_v3);
        fprintf(f4,"\n");
        fclose(f4);

        FILE * f5 = fopen(v_4_values, "a");
        fprintf(f5,"%d, ",choice_v4);
        fprintf(f5,"\n");
        fclose(f5);

        FILE * f6 = fopen(bits_values, "a");
        for(int pp=0;pp<no_words_all_secrets;pp++)
            fprintf(f6,"%08x, ", decrypt_success_matrix[no_trials][pp]);
        fprintf(f6,"\n");
        fclose(f6);

        no_trials = no_trials+1;
    }

    // Writing trans_decrypt_success_matrix to text file...

    FILE * ftrans = fopen(trans_bits_values, "w+");
    for(int pp=0;pp<no_words_all_trials;pp++)
    {
        for(int ppp=0;ppp<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);ppp++)
        {
            fprintf(ftrans,"%08x, ", trans_decrypt_success_matrix[pp][ppp]);
        }
    }
    fprintf(ftrans,"\n");
    fclose(ftrans);

    }

    // In this loop, we basically try to identify the candidate tuples which are still not resolvable and estimate the
    // average attacker's complexity in terms of number of queries for full key recovery based on the chosen ciphertexts and the number of conflicts...
    // Estimation is done in a manner similar to a knock-out tournament (2^k players in k stages)...

    if(strcmp(argv[1],"compute_complexity") == 0)
    {

        // We simply read the trans_decrypt_success_matrix from the text file and then test how many secret candidate tuples still are not
        // distinguishable (same columns) and estimate attacker's complexity...

    int col_1 = 0;
    int col_2 = 0;
    int element = 0;
    int same_element_row_count = 0;
    int total_matches = 0;

    uint32_t current_row[no_words_all_trials];
    int flag_went_into_no_collected = 0;
    sprintf(trans_bits_values,"trans_bits_values.dat");
    FILE *ftrans = fopen(trans_bits_values, "r");

    uint32_t trans_entry;
    for(int pp=0;pp<no_words_all_trials;pp++)
    {
        for(int ppp=0;ppp<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);ppp++)
        {
            fscanf(ftrans,"%08x,", &trans_entry);
            trans_decrypt_success_matrix[pp][ppp] = trans_entry;
        }
        fscanf(ftrans," \n");
    }
    fclose(ftrans);

    // Collecting only the unique columns in the trans_decrypt_success_matrix...

    uint32_t **unique_rows_collection = (uint32_t **)malloc((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1) * sizeof(uint32_t*));
    for(int i = 0; i < (2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1); i++)
    {
      unique_rows_collection[i] = (uint32_t *)malloc(no_words_all_trials * sizeof(uint32_t));
    }

    no_collected = 0;

    for(col_1 = 0; col_1<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1) ; col_1++)
    {
        for(col_2 = 0; col_2<no_words_all_trials ; col_2++)
        {
            current_row[col_2] = trans_decrypt_success_matrix[col_2][col_1];
        }

        if(no_collected == 0)
        {
            for(int uu=0;uu<no_words_all_trials;uu++)
                unique_rows_collection[0][uu] = current_row[uu];
            flag_went_into_no_collected = 1;
        }
        else
        {
            int same_row_found_flag = 0;
            for(int yy=0;yy<no_collected;yy++)
            {
                int same_sum = 0;
                for(int zz=0;zz<no_words_all_trials;zz++)
                {
                    if(unique_rows_collection[yy][zz] == current_row[zz])
                        same_sum++;
                }
                if(same_sum == no_words_all_trials)
                {
                    same_row_found_flag = 1;
                    // Found same row...
                    break;
                }
            }
            if(same_row_found_flag == 0)
            {
                // If found new row, then add it to the unique collection...
                for(int yy=0;yy<no_words_all_trials;yy++)
                {
                    unique_rows_collection[no_collected][yy] = current_row[yy];
                }
                no_collected = no_collected+1;
            }
        }

        if(flag_went_into_no_collected == 1)
        {
            no_collected = no_collected+1;
            flag_went_into_no_collected = 0;
        }
    }

    // Number of unique columns collected in trans_decrypt_success_matrix...

    // printf("No of clusters collected: %d\n",no_collected);
    sprintf(greatest_sum_no_collected,"greatest_sum_no_collected.dat");

    FILE *f8 = fopen(greatest_sum_no_collected, "w+");
    fprintf(f8,"%d, ", no_collected); // Writing total number of unique columns...

    int collision_rows_number[no_collected];

    sprintf(colliding_rows,"colliding_rows.dat");
    FILE *f5 = fopen(colliding_rows, "a");
    float resolve_complexity = 0;
    for(col_1 = 0;col_1<no_collected;col_1++)
    {
        int sum = 0;
        float prob_calc = 0;
        for(col_2 = 0;col_2<(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);col_2++)
        {
            int same_sum = 0;
            for(int col_3 = 0;col_3<no_words_all_trials;col_3++)
            {
                if(unique_rows_collection[col_1][col_3] == trans_decrypt_success_matrix[col_3][col_2])
                    same_sum++;
            }
            if(same_sum == no_words_all_trials)
            {
                choice1 = ((int)col_2/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)));
                choice2 = (((int)col_2/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)))%(2*NEWHOPE_K+1));
                choice3 = (((int)col_2/(2*NEWHOPE_K+1))%(2*NEWHOPE_K+1));
                choice4 = ((int)col_2%(2*NEWHOPE_K+1));
                fprintf(f5,"%d, ", col_2); // Writing colliding column numbers in collision_rows.dat text file...
                prob_calc = prob_calc + (probabilities[choice1]*probabilities[choice2]*probabilities[choice3]*probabilities[choice4]);
                sum++;
            }
        }
        fprintf(f5,"\n");
        collision_rows_number[col_1] = sum;
        float base_2 = ceil(log2(sum));
        float summm = ((float)pow(2, base_2) - 1)*prob_calc;  // Assuming ceil(log_2(n)) stages in the case of "n" unresolved candidate tuples which works like a knock out tournament to select the best winner...
        resolve_complexity = resolve_complexity + summm;
    }
    fclose(f5);

    printf("Average Attacker Complexity: %5.10f\n",resolve_complexity+MAX_TRIALS); // This prints the estimated attacker's complexity assuming CBD distribution of the secret coefficients and ceil(log_2(n)) stages in the case of "n" unresolved candidate tuples...

    sprintf(colliding_rows_numbers,"colliding_rows_numbers.dat");
    FILE *f6 = fopen(colliding_rows_numbers, "w+");
    for(int yy=0;yy<no_collected;yy++)
    {
        fprintf(f6,"%d, ", collision_rows_number[yy]); // This prints the number of colliding elements in each cluster.... minimum value is 1 when there is no collision.
    }
    fclose(f6);

    greatest_sum = 0;

    for(int yy=0;yy<no_collected;yy++)
    {
        if(collision_rows_number[yy] > greatest_sum)
            greatest_sum = collision_rows_number[yy];
    }

    // printf("Max conflicts in a cluster:%d\n",greatest_sum); // Just printing our the maximum number of candidate tuples in any given cluster... this should be strictly less than MAX_CLASHES... because we use MAX_CLASHES for initializing an array... we do not known "greatest_sum" before hand...
    fprintf(f8,"%d, ", greatest_sum);
    fclose(f8);

    }

    // In this loop, we actually resolve the conflict in a pairwise fashion between every candidate tuple in every cluster... So, in a cluster with n candidates, we need n choose 2 number of ciphertexts to resolve the conflict... we store all these additional ciphertexts in the text file...

    if(strcmp(argv[1],"resolve_conflicts") == 0)
    {

    sprintf(greatest_sum_no_collected,"greatest_sum_no_collected.dat");
    sprintf(colliding_rows,"colliding_rows.dat");
    sprintf(colliding_rows_numbers,"colliding_rows_numbers.dat");

    sprintf(u_values,"u_values_resolved.dat");
    FILE * f1 = fopen(u_values, "w+");
    fclose(f1);

    sprintf(v_1_values,"v_1_values_resolved.dat");
    FILE * f2 = fopen(v_1_values, "w+");
    fclose(f2);

    sprintf(v_2_values,"v_2_values_resolved.dat");
    FILE * f3 = fopen(v_2_values, "w+");
    fclose(f3);

    sprintf(v_3_values,"v_3_values_resolved.dat");
    FILE * f4 = fopen(v_3_values, "w+");
    fclose(f4);

    sprintf(v_4_values,"v_4_values_resolved.dat");
    FILE * f8 = fopen(v_4_values, "w+");
    fclose(f8);

    sprintf(collision_bits_values,"collision_bits_values.dat");
    FILE * f_collision_bits = fopen(collision_bits_values, "w+");
    fclose(f_collision_bits);

    FILE *f6 = fopen(colliding_rows, "r");
    FILE *f5 = fopen(colliding_rows_numbers, "r");

    FILE * f7 = fopen(greatest_sum_no_collected, "r");
    int read_int;
    int col_row_no;
    fscanf(f7, "%d,", &no_collected);
    fscanf(f7, "%d,", &greatest_sum);
    fclose(f7);
    printf("Greatest Sum: %d, %d\n",no_collected,greatest_sum);
    int current_conflicted_rows[greatest_sum];

    int no_success = 0;
    int no_failure = 0;
    int bits_match[2];

    int total_tries = 0;
    int total_conflicted = 0;
    int current_conflicted_pair_rows[2];
    int no_conflicted;

    // This loop runs for every cluster collected...
    for(int yy=0;yy<no_collected;yy++)
    {
        fscanf(f5, "%d,", &col_row_no); // Get the current collision number from reading collision_rows_numbers.dat...
        no_conflicted = col_row_no;
        printf("Resolving Cluster: %d/%d with %d candidates...\n",yy,no_collected,no_conflicted);
        for(int yyy = 0; yyy < col_row_no; yyy++)
        {
            fscanf(f6, "%d,", &read_int);
            current_conflicted_rows[yyy] = read_int; // Reading currently conflicted candidates in the current cluster from the collision_rows.dat file....
        }
        fscanf(f6, " \n");

        // Resolve conflict if the number of conflicted tuples is greater than 1...
        if(no_conflicted > 1)
        {
            double trials = 1;
            int MAX_TRIALS = 1;

            int max_attempts = (no_chosen_u)*8*8*8*8;
            int comb_no = 0;
            int u_count = 0;
            int v_1_count = 0;
            int v_2_count = 0;
            int v_3_count = 0;
            int v_4_count = 0;

            total_tries += no_conflicted*no_conflicted*(no_conflicted-1)/2;
            total_conflicted += no_conflicted;

            // Iterating over every pair of conflicted tuples...

            for(int tt = 0;tt<no_conflicted;tt++)
            {
                for(int qq = tt+1;qq<no_conflicted;qq++)
                {
                    comb_no++;
                    current_conflicted_pair_rows[0] = current_conflicted_rows[tt];
                    current_conflicted_pair_rows[1] = current_conflicted_rows[qq];
                    int rep_flag = 1;
                    int no_attempts = 0;

                    // checked whether you have tried all possible values of ciphertext for the given pair and the conflict is still not resolved, then exit the program...

                    while(no_attempts < max_attempts)
                    {
                        // Iterating over all possible values of u0, v0, v1, v2, v3...

                        for(u_count = 0;u_count < no_chosen_u;u_count++)
                        {
                            for(v_1_count = 0;v_1_count < 8;v_1_count++)
                            {
                                for(v_2_count = 0;v_2_count < 8;v_2_count++)
                                {
                                    for(v_3_count = 0;v_3_count < 8;v_3_count++)
                                    {
                                        for(v_4_count = 0;v_4_count < 8;v_4_count++)
                                        {
                                            choice_u  = chosen_u[u_count];
                                            choice_v1 = chosen_v[v_1_count];
                                            choice_v2 = chosen_v[v_2_count];
                                            choice_v3 = chosen_v[v_3_count];
                                            choice_v4 = chosen_v[v_4_count];

                                            for(int iii=0;iii<2;iii++)
                                            {
                                                choice1 = ((int)current_conflicted_pair_rows[iii]/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1))) - NEWHOPE_K;
                                                choice2 = (((int)current_conflicted_pair_rows[iii]/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)))%(2*NEWHOPE_K+1)) - NEWHOPE_K;
                                                choice3 = (((int)current_conflicted_pair_rows[iii]/(2*NEWHOPE_K+1))%(2*NEWHOPE_K+1)) - NEWHOPE_K;
                                                choice4 = ((int)current_conflicted_pair_rows[iii]%(2*NEWHOPE_K+1)) - NEWHOPE_K;
                                                temp1 = (((choice_u*choice1) % NEWHOPE_Q) + 3*NEWHOPE_Q - choice_v1) % NEWHOPE_Q;
                                                if(temp1 < 0)
                                                    temp1 = temp1 + NEWHOPE_Q;

                                                temp2 = (((choice_u*choice2) % NEWHOPE_Q) + 3*NEWHOPE_Q - choice_v2) % NEWHOPE_Q;
                                                if(temp2 < 0)
                                                    temp2 = temp2 + NEWHOPE_Q;

                                                temp3 = (((choice_u*choice3) % NEWHOPE_Q) + 3*NEWHOPE_Q - choice_v3) % NEWHOPE_Q;
                                                if(temp3 < 0)
                                                    temp3 = temp3 + NEWHOPE_Q;

                                                temp4 = (((choice_u*choice4) % NEWHOPE_Q) + 3*NEWHOPE_Q - choice_v4) % NEWHOPE_Q;
                                                if(temp4 < 0)
                                                    temp4 = temp4 + NEWHOPE_Q;

                                                t  = flipabs(temp1);
                                                t += flipabs(temp2);
                                                t += flipabs(temp3);
                                                t += flipabs(temp4);
                                                t = ((t - NEWHOPE_Q));

                                                t >>= 15;

                                                bits_match[iii] = t;
                                            }

                                            int bits_matching_or_not = 0;
                                            if(bits_match[0] != bits_match[1])
                                            {
                                                // Found a distinguisher and hence this ciphertext choice resolves the conflict and save this in the text file...
                                                bits_matching_or_not = 1;
                                            }
                                            else
                                            {
                                                // Not found a distinguisher....
                                            }

                                            if(bits_matching_or_not == 1)
                                            {
                                                // Saving the distinguising ciphertext in text file...
                                                rep_flag = 0;
                                                no_success++;
                                                f1 = fopen(u_values, "a");
                                                fprintf(f1, "%d *** %d\n",current_conflicted_pair_rows[0],current_conflicted_pair_rows[1]);
                                                fprintf(f1,"%d, ",choice_u);
                                                fprintf(f1,"\n");

                                                f2 = fopen(v_1_values, "a");
                                                fprintf(f2, "%d *** %d\n",current_conflicted_pair_rows[0],current_conflicted_pair_rows[1]);
                                                fprintf(f2,"%d, ",v_1_count);
                                                fprintf(f2,"\n");

                                                f3 = fopen(v_2_values, "a");
                                                fprintf(f3, "%d *** %d\n",current_conflicted_pair_rows[0],current_conflicted_pair_rows[1]);
                                                fprintf(f3,"%d, ",v_2_count);
                                                fprintf(f3,"\n");

                                                f4 = fopen(v_3_values, "a");
                                                fprintf(f4, "%d *** %d\n",current_conflicted_pair_rows[0],current_conflicted_pair_rows[1]);
                                                fprintf(f4,"%d, ",v_3_count);
                                                fprintf(f4,"\n");

                                                f8 = fopen(v_4_values, "a");
                                                fprintf(f8, "%d *** %d\n",current_conflicted_pair_rows[0],current_conflicted_pair_rows[1]);
                                                fprintf(f8,"%d, ",v_4_count);
                                                fprintf(f8,"\n");

                                                f_collision_bits = fopen(collision_bits_values, "a");
                                                fprintf(f_collision_bits, "%d *** %d\n",current_conflicted_pair_rows[0],current_conflicted_pair_rows[1]);
                                                fprintf(f_collision_bits,"%d, ", bits_match[0]);
                                                fprintf(f_collision_bits,"%d, ", bits_match[1]);
                                                fprintf(f_collision_bits,"\n");

                                                fclose(f1);
                                                fclose(f2);
                                                fclose(f3);
                                                fclose(f4);
                                                fclose(f8);
                                                fclose(f_collision_bits);

                                            }
                                            else
                                            {
                                            }
                                            no_attempts = no_attempts+1;
                                            if(rep_flag == 0)
                                                break;
                                        }
                                        if(rep_flag == 0)
                                            break;
                                    }
                                    if(rep_flag == 0)
                                        break;
                                }
                                if(rep_flag == 0)
                                    break;
                            }
                            if(rep_flag == 0)
                                break;
                        }
                        if(no_attempts == max_attempts)
                        {
                            // Failure to resolve conflict for a given candidate pair... Then exit the program...
                            printf("Failure...\n");
                            no_failure++;
                            return -1;
                        }
                        if(rep_flag == 0)
                            break;
                    }
                }
            }
        }
        printf("Resolved...\n");
    }
    fclose(f5);
    fclose(f6);

    }

    // Now, that we have collected all the ciphertexts, let us perform the actual attack on NewHope1024...

    if(strcmp(argv[1],"run_attacks") == 0)
    {
        sprintf(colliding_rows,"colliding_rows.dat");
        sprintf(colliding_rows_numbers,"colliding_rows_numbers.dat");

        int total_attacks = atoi(argv[2]);
        float trace_complexity = 0;
        float success_rate = 0;

        FILE *f_s_coeffs = fopen("f_correct_secrets.dat", "w+");
        fclose(f_s_coeffs);

        FILE *f_s_coeffs_guessed = fopen("f_guessed_secrets.dat", "w+");
        fclose(f_s_coeffs_guessed);

        // Number of attacks to be performed... (Number of secret keys to be retrieved...)
        for(int no_attacks = 0 ; no_attacks < total_attacks; no_attacks++)
        {
            printf("No Attack: %d\n",no_attacks);
            // Generate a new key pair...
            poly shat;
            int s_coeffs[NEWHOPE_N];
            int guessed_s_coeffs[NEWHOPE_N];
            crypto_kem_keypair(pk+8, sk_a+8);

            poly_frombytes(&shat, sk_a+8);
            poly_invntt(&shat);

            // Saving the correct secrets in the f_correct_secrets.dat text file...

            f_s_coeffs = fopen("f_correct_secrets.dat", "a");
            fprintf(f_s_coeffs, "\n*****Secret %d*****\n",no_attacks);

            for(int i = 0;i < NEWHOPE_N;i++)
            {
                if(shat.coeffs[i] >= NEWHOPE_Q)
                {
                    s_coeffs[i] = shat.coeffs[i] - NEWHOPE_Q;
                }
                else if(shat.coeffs[i] >= (NEWHOPE_Q - NEWHOPE_K) && shat.coeffs[i] < NEWHOPE_Q)
                {
                    s_coeffs[i] = -1*(NEWHOPE_Q - shat.coeffs[i]);
                }
                else
                {
                    s_coeffs[i] = shat.coeffs[i];
                }
                fprintf(f_s_coeffs, "%d, ",s_coeffs[i]);
            }
            fprintf(f_s_coeffs, "\n");
            fclose(f_s_coeffs);

            FILE * f1;

            sprintf(bits_values,"bits_values.dat");
            sprintf(u_values,"u_values.dat");
            sprintf(v_1_values,"v_1_values.dat");
            sprintf(v_2_values,"v_2_values.dat");
            sprintf(v_3_values,"v_3_values.dat");
            sprintf(v_4_values,"v_4_values.dat");

            int u_value_now, v_1_value_now, v_2_value_now, v_3_value_now, v_4_value_now;

            uint8_t bits_oracle[MAX_TRIALS];
            int success = 0;
            int extra_trials = 0;
            char temp_string_2[6*no_words_all_secrets];
            char temp_string[6*no_words_all_secrets];
            int temp_numbers[no_words_all_secrets];

            // Secrets are retrieved four coefficients at a time... so for NewHope1024, we need to do it 256 times...

            for(int secret_index = 0;secret_index < NEWHOPE_N/4; secret_index++)
            {
                if(secret_index == 0)
                {
                    int temp_calc = (s_coeffs[768]+(NEWHOPE_K))+(s_coeffs[512]+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(s_coeffs[256]+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(s_coeffs[0]+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);
                }
                else
                {
                    int temp_calc = (s_coeffs[(3*NEWHOPE_N/4)-secret_index]+(NEWHOPE_K))+(s_coeffs[(NEWHOPE_N/2)-secret_index]+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(s_coeffs[(NEWHOPE_N/4)-secret_index]+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(-1*(s_coeffs[NEWHOPE_N-secret_index])+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);
                }

                FILE * f2 = fopen(u_values, "r");
                FILE * f3 = fopen(v_1_values, "r");
                FILE * f4 = fopen(v_2_values, "r");
                FILE * f5 = fopen(v_3_values, "r");
                FILE * f6 = fopen(v_4_values, "r");

                // Here, we run decapsulation of NewHope1024 with the initially chosen MAX_TRIALS number of ciphertexts to narrow down the search space for the candidate tuple...
                // Here, we simulate the oracle's responses by letting the decapsulation procedure return 1 if the lsb of the message is 1 or 0 otherwise...
                // In the real experiment, it will be replaced with an EM side-channel oracle... In our attack simulations, we assume a perfect oracle...

                for(int i = 0;i<MAX_TRIALS;i++)
                {
                    fscanf(f2, "%d,\n",&u_value_now);
                    fscanf(f3, "%d,\n",&v_1_value_now);
                    fscanf(f4, "%d,\n",&v_2_value_now);
                    fscanf(f5, "%d,\n",&v_3_value_now);
                    fscanf(f6, "%d,\n",&v_4_value_now);

                    // Create ciphertexts based on the chosen values...
                    crypto_kem_enc(sendb+8, key_b+8, pk+8, secret_index, u_value_now, v_1_value_now, v_2_value_now, v_3_value_now, v_4_value_now);

                    // Get the oracle's binary response and store in the array bits_oracle...
                    bits_oracle[i] = crypto_kem_dec(key_a+8, sendb+8, sk_a+8);
                }
                fclose(f2);
                fclose(f3);
                fclose(f4);
                fclose(f5);
                fclose(f6);

                // Now compare the bits_oracle array with all entries in decrypt_success_matrix for each candidate tuple...and identify the cluster of possible candidate tuples or unique candidate...

                uint32_t temp_bit_value;
                uint32_t bit_values_now[MAX_TRIALS];
                int no_matches = 0;
                int matching_secret_combo[MAX_CLASHES];

                int found_match = 0;
                for(int j = 0;j < no_words_all_secrets; j++)
                {
                    f1 = fopen(bits_values, "r");

                    for(int i = 0;i<MAX_TRIALS;i++)
                    {
                        for(int k = 0;k < j; k++)
                        {
                            fscanf(f1, "%08x, ",&temp_bit_value);
                        }
                        fscanf(f1, "%08x, ",&bit_values_now[i]);

                        for(int k = 0;k < (no_words_all_secrets - j - 1); k++)
                        {
                            fscanf(f1, "%s\n",temp_string_2);
                        }
                        fscanf(f1, "\n");
                    }
                    fclose(f1);

                    uint8_t bits_checked_now[MAX_TRIALS];
                    for(int i = 0;i<32;i++)
                    {
                        int sum_matching = 0;
                        for(int hh = 0; hh < MAX_TRIALS;hh++)
                        {
                            bits_checked_now[hh] = (bit_values_now[hh]>>i)&0x1;
                            if(bits_oracle[hh] == bits_checked_now[hh])
                                sum_matching++;
                        }

                        if(sum_matching == MAX_TRIALS)
                        {
                            matching_secret_combo[no_matches] = j*32+i;
                            no_matches++;
                            found_match = 1; // Exit when a matching candidate tuple is found...
                            break;
                        }
                    }
                    if(found_match == 1)
                        break;   // Exit when a matching candidate tuple is found...
                }

                // Once a matching candidate is found, find if there are other candidate tuples conflict based on the values in the
                // collision_rows.dat file...

                if(found_match == 1)
                {
                    FILE * fcolliding_rows = fopen(colliding_rows, "r");
                    FILE * fcolliding_rows_numbers = fopen(colliding_rows_numbers, "r");

                    int found_row = 0;
                    int collision_no = 0;
                    int current_row_first_element = 0;
                    int current_row_no = 0;

                    while(found_row == 0)
                    {
                        fscanf(fcolliding_rows_numbers, "%d, ",&collision_no);
                        fscanf(fcolliding_rows, "%d, ",&current_row_first_element); // Checking first element...
                        if(matching_secret_combo[0] == current_row_first_element)
                        {
                            found_row = 1;
                            for(int ooo = 0;ooo < collision_no-1 ; ooo++)
                            {
                                fscanf(fcolliding_rows, "%d, ",&current_row_first_element);
                                matching_secret_combo[ooo+1] = current_row_first_element;
                                no_matches++;
                            }
                            fscanf(fcolliding_rows, "\n");
                        }
                        else
                        {
                            current_row_no++;
                            for(int ooo = 0;ooo < collision_no-1 ; ooo++)
                                fscanf(fcolliding_rows, "%d, ",&current_row_first_element);
                            fscanf(fcolliding_rows, "\n");
                        }
                    }
                    fclose(fcolliding_rows);
                    fclose(fcolliding_rows_numbers);
                }

                // printf("\n");
                // printf("no_matches: %d\n",no_matches); // Number of conflicting candidate tuples... minimum value is 1...

                if(no_matches == 0)
                {
                    printf("Failure..\n"); // No match found... exit program...
                    return -1;
                }
                else if(no_matches == 1) // Only one candidate tuple is found... successful...
                {
                    choice1 = ((int)matching_secret_combo[0]/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1))) - NEWHOPE_K;
                    choice2 = (((int)matching_secret_combo[0]/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)))%(2*NEWHOPE_K+1)) - NEWHOPE_K;
                    choice3 = (((int)matching_secret_combo[0]/(2*NEWHOPE_K+1))%(2*NEWHOPE_K+1)) - NEWHOPE_K;
                    choice4 = ((int)matching_secret_combo[0]%(2*NEWHOPE_K+1)) - NEWHOPE_K;

                    int coeff1, coeff2, coeff3, coeff4;

                    if(secret_index == 0)
                    {
                        if((choice1 == s_coeffs[0]) && (choice2 == s_coeffs[(NEWHOPE_N/4)]) && (choice3 == s_coeffs[(NEWHOPE_N/2)]) && (choice4 == s_coeffs[(3*NEWHOPE_N/4)]))
                        {
                            coeff1 = s_coeffs[0];
                            coeff2 = s_coeffs[(NEWHOPE_N/4)];
                            coeff3 = s_coeffs[(NEWHOPE_N/2)];
                            coeff4 = s_coeffs[(3*NEWHOPE_N/4)];
                            success++;

                            int temp_calc = (coeff4+(NEWHOPE_K))+(coeff3+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(coeff2+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(coeff1+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);

                            // Saving the guessed coefficients in guessed_s_coeffs...

                            guessed_s_coeffs[0] = coeff1;
                            guessed_s_coeffs[(NEWHOPE_N/4)] = coeff2;
                            guessed_s_coeffs[(NEWHOPE_N/2)] = coeff3;
                            guessed_s_coeffs[(3*NEWHOPE_N/4)] = coeff4;
                        }
                    }
                    else if(secret_index > 0)
                    {
                        if(choice1 == -1*(s_coeffs[NEWHOPE_N-secret_index]) && choice2 == s_coeffs[(NEWHOPE_N/4)-secret_index] && choice3 == s_coeffs[(NEWHOPE_N/2)-secret_index] && choice4 == s_coeffs[(3*NEWHOPE_N/4)-secret_index])
                        {
                            coeff1 = -1*(s_coeffs[NEWHOPE_N-secret_index]);
                            coeff2 = s_coeffs[(NEWHOPE_N/4)-secret_index];
                            coeff3 = s_coeffs[(NEWHOPE_N/2)-secret_index];
                            coeff4 = s_coeffs[(3*NEWHOPE_N/4)-secret_index];
                            success++;
                            int temp_calc = (coeff4+(NEWHOPE_K))+(coeff3+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(coeff2+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(coeff1+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);

                            // Saving the guessed coefficients in guessed_s_coeffs...

                            guessed_s_coeffs[NEWHOPE_N-secret_index] = -1*coeff1;
                            guessed_s_coeffs[(NEWHOPE_N/4)-secret_index] = coeff2;
                            guessed_s_coeffs[(NEWHOPE_N/2)-secret_index] = coeff3;
                            guessed_s_coeffs[(3*NEWHOPE_N/4)-secret_index] = coeff4;
                        }
                    }
                    printf("Success: %d/%d\n",success,(secret_index+1));
                }

                // There are multiple conflicting candidate tuples... Hence, we need to resolve the conflict... Now, we need to do the second stage....

                else if(no_matches > 1)
                {
                    sprintf(u_values_resolved,"u_values_resolved.dat");
                    sprintf(v_1_values_resolved,"v_1_values_resolved.dat");
                    sprintf(v_2_values_resolved,"v_2_values_resolved.dat");
                    sprintf(v_3_values_resolved,"v_3_values_resolved.dat");
                    sprintf(v_4_values_resolved,"v_4_values_resolved.dat");
                    sprintf(bits_values_resolved,"collision_bits_values.dat");

                    FILE * fcolliding_rows = fopen(colliding_rows, "r");
                    FILE * fcolliding_rows_numbers = fopen(colliding_rows_numbers, "r");

                    int found_row = 0;
                    int collision_no = 0;
                    int current_row_first_element = 0;
                    int current_row_no = 0;

                    // Identify the row in which the conflicting candidates are present in the collision_rows.dat file, result in "current_row_no"...

                    while(found_row == 0)
                    {
                        fscanf(fcolliding_rows_numbers, "%d, ",&collision_no);
                        fscanf(fcolliding_rows, "%d, ",&current_row_first_element); // Checking first element...
                        if(matching_secret_combo[0] == current_row_first_element)
                        {
                            found_row = 1;
                            for(int ooo = 0;ooo < collision_no-1 ; ooo++)
                                fscanf(fcolliding_rows, "%d, ",&current_row_first_element);
                            fscanf(fcolliding_rows, "\n");
                        }
                        else
                        {
                            current_row_no++;
                            for(int ooo = 0;ooo < collision_no-1 ; ooo++)
                                fscanf(fcolliding_rows, "%d, ",&current_row_first_element);
                            fscanf(fcolliding_rows, "\n");
                        }
                    }
                    fclose(fcolliding_rows);
                    fclose(fcolliding_rows_numbers);

                    fcolliding_rows_numbers = fopen(colliding_rows_numbers, "r");

                    int lines_to_traverse = 0;
                    for(int ii = 0;ii < current_row_no; ii++)
                    {
                        fscanf(fcolliding_rows_numbers, "%d, ",&collision_no);
                        lines_to_traverse = lines_to_traverse + ((collision_no)*(collision_no-1));
                    }
                    fclose(fcolliding_rows_numbers);

                    // Find the number of lines to traverse to identify the relevant information within the text files to resolve the conflict for the cluster we are dealing with....
                    // Found the line in which values are, so now we use these values to resolve the conflict in a pairwise manner... similar to a knockout tournament...

                    int no_stages = ceil(log2(no_matches)); // No of stages to resolve the conflict... (knock out tournament approach - Group in pairs in each stage until you have one winner...)
                    int current_match_length;
                    int bits_array_length = no_matches;
                    int bits_resolve[bits_array_length];
                    int bits_resolve_positions[bits_array_length];
                    int temp_ints_1, temp_ints_2, temp_ints_3;
                    int bits_1, bits_2;

                    for(int uuu = 0;uuu < bits_array_length;uuu++)
                        bits_resolve_positions[uuu] = uuu;

                    for(int ii = 0;ii < no_stages; ii++)
                    {
                        // In each stage, we split the number of surviving candidates in pairs and resolve the conflict by querying the oracle and matching with our guessed response...

                        for(int jj = 0;jj < bits_array_length; jj = jj+2)
                        {
                            if(bits_array_length % 2 == 0 || jj != bits_array_length-1)
                            {
                                FILE *fu_values = fopen(u_values_resolved, "r");
                                FILE *fv_1_values = fopen(v_1_values_resolved, "r");
                                FILE *fv_2_values = fopen(v_2_values_resolved, "r");
                                FILE *fv_3_values = fopen(v_3_values_resolved, "r");
                                FILE *fv_4_values = fopen(v_4_values_resolved, "r");
                                FILE * fbits_values = fopen(bits_values_resolved, "r");

                                // Calculating lines to traverse based on the pair of candidate tuples we are dealing with, to retrieve the appropriate ciphertext to query from the text files...

                                int lines_extra = 0;
                                for(int ll = 0; ll < bits_resolve_positions[jj]; ll++)
                                {
                                    lines_extra = lines_extra + (no_matches - (ll+1));
                                }
                                lines_extra = lines_extra + (bits_resolve_positions[jj+1] -  bits_resolve_positions[jj] - 1);
                                lines_extra = lines_extra*2;

                                for(int kk = 0;kk<lines_to_traverse+lines_extra;kk = kk+2)
                                {
                                    fscanf(fbits_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                    fscanf(fbits_values,"%d, %d, \n",&temp_ints_1,&temp_ints_2);

                                    fscanf(fu_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                    fscanf(fu_values,"%d, \n",&temp_ints_1);

                                    fscanf(fv_1_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                    fscanf(fv_1_values,"%d, \n",&temp_ints_1);

                                    fscanf(fv_2_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                    fscanf(fv_2_values,"%d, \n",&temp_ints_1);

                                    fscanf(fv_3_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                    fscanf(fv_3_values,"%d, \n",&temp_ints_1);

                                    fscanf(fv_4_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                    fscanf(fv_4_values,"%d, \n",&temp_ints_1);
                                }

                                fscanf(fbits_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                fscanf(fu_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                fscanf(fv_1_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                fscanf(fv_2_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                fscanf(fv_3_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);
                                fscanf(fv_4_values,"%d *** %d\n",&temp_ints_1,&temp_ints_2);

                                // Reading the correct ciphertext values corresponding to the candidate pair we are dealing with....we seek to resolve...

                                fscanf(fbits_values,"%d, %d\n",&bits_1,&bits_2);
                                fscanf(fu_values,"%d, \n",&u_value_now);
                                fscanf(fv_1_values,"%d, \n",&v_1_value_now);
                                fscanf(fv_2_values,"%d, \n",&v_2_value_now);
                                fscanf(fv_3_values,"%d, \n",&v_3_value_now);
                                fscanf(fv_4_values,"%d, \n",&v_4_value_now);

                                extra_trials++;

                                // Generating the corresponding ciphertext...

                                crypto_kem_enc(sendb+8, key_b+8, pk+8, secret_index, u_value_now, v_1_value_now, v_2_value_now,  v_3_value_now, v_4_value_now);

                                // Querying the oracle... generating the ciphertext...

                                temp_ints_1 = crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

                                // Choosing the correct candidate and placing in the front part of the list of surviving candidates and only cosidering that part of the list for the next stage...

                                if(temp_ints_1 == bits_1)
                                {
                                    bits_resolve_positions[(jj/2)] = bits_resolve_positions[jj];
                                }
                                else if(temp_ints_1 == bits_2)
                                {
                                    bits_resolve_positions[(jj/2)] = bits_resolve_positions[jj+1];
                                }

                                fclose(fu_values);
                                fclose(fv_1_values);
                                fclose(fv_2_values);
                                fclose(fv_3_values);
                                fclose(fv_4_values);
                                fclose(fbits_values);

                            }
                            else if(jj == bits_array_length-1)
                            {
                                bits_resolve_positions[(jj/2)] = bits_resolve_positions[jj];
                            }
                        }

                        // The list length halves at each stage and only the surviving candidates are again tested....

                        if(bits_array_length%2 == 0)
                        {
                            bits_array_length = bits_array_length/2;
                        }
                        else
                        {
                            bits_array_length = (int)(bits_array_length/2)+1;
                        }
                    }

                    // Thus, the first element in the list after all the stages will be the final surviving element...

                    choice1 = ((int)matching_secret_combo[bits_resolve_positions[0]]/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1))) - NEWHOPE_K;
                    choice2 = (((int)matching_secret_combo[bits_resolve_positions[0]]/((2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)))%(2*NEWHOPE_K+1)) - NEWHOPE_K;
                    choice3 = (((int)matching_secret_combo[bits_resolve_positions[0]]/(2*NEWHOPE_K+1))%(2*NEWHOPE_K+1)) - NEWHOPE_K;
                    choice4 = ((int)matching_secret_combo[bits_resolve_positions[0]]%(2*NEWHOPE_K+1)) - NEWHOPE_K;

                    int coeff1, coeff2, coeff3, coeff4;

                    if(secret_index == 0)
                    {
                        if((choice1 == s_coeffs[0]) && (choice2 == s_coeffs[(NEWHOPE_N/4)]) && (choice3 == s_coeffs[(NEWHOPE_N/2)]) && (choice4 == s_coeffs[(3*NEWHOPE_N/4)]))
                        {
                            coeff1 = s_coeffs[0];
                            coeff2 = s_coeffs[(NEWHOPE_N/4)];
                            coeff3 = s_coeffs[(NEWHOPE_N/2)];
                            coeff4 = s_coeffs[(3*NEWHOPE_N/4)];
                            success++;
                            int temp_calc = (coeff4+(NEWHOPE_K))+(coeff3+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(coeff2+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(coeff1+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);

                            // Storing guessed candidate tuple in guessed_s_coeffs....
                            guessed_s_coeffs[0] = coeff1;
                            guessed_s_coeffs[(NEWHOPE_N/4)] = coeff2;
                            guessed_s_coeffs[(NEWHOPE_N/2)] = coeff3;
                            guessed_s_coeffs[(3*NEWHOPE_N/4)] = coeff4;
                        }
                    }
                    else if(secret_index > 0)
                    {

                        if(choice1 == -1*(s_coeffs[NEWHOPE_N-secret_index]) && choice2 == s_coeffs[(NEWHOPE_N/4)-secret_index] && choice3 == s_coeffs[(NEWHOPE_N/2)-secret_index] && choice4 == s_coeffs[(3*NEWHOPE_N/4)-secret_index])
                        {
                            coeff1 = -1*(s_coeffs[NEWHOPE_N-secret_index]);
                            coeff2 = s_coeffs[(NEWHOPE_N/4)-secret_index];
                            coeff3 = s_coeffs[(NEWHOPE_N/2)-secret_index];
                            coeff4 = s_coeffs[(3*NEWHOPE_N/4)-secret_index];
                            success++;
                            int temp_calc = (coeff4+(NEWHOPE_K))+(coeff3+(NEWHOPE_K))*(2*NEWHOPE_K+1)+(coeff2+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)+(coeff1+(NEWHOPE_K))*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1)*(2*NEWHOPE_K+1);

                            // Storing guessed candidate tuple in guessed_s_coeffs....

                            guessed_s_coeffs[NEWHOPE_N-secret_index] = -1*coeff1;
                            guessed_s_coeffs[(NEWHOPE_N/4)-secret_index] = coeff2;
                            guessed_s_coeffs[(NEWHOPE_N/2)-secret_index] = coeff3;
                            guessed_s_coeffs[(3*NEWHOPE_N/4)-secret_index] = coeff4;
                        }
                    }

                    printf("Success: %d/%d\n",success,(secret_index+1));
                }
            }

            // Calculating actual number of queries for every attack...

            trace_complexity = trace_complexity + (float)(extra_trials + (NEWHOPE_N/4)*(MAX_TRIALS));
            success_rate = success_rate + (float)success/(NEWHOPE_N/4);
            printf("Total No of Traces: %f\n",trace_complexity);

            // Storing retrieved guessed secret in f_guessed_secrets.dat file...

            f_s_coeffs_guessed = fopen("f_guessed_secrets.dat", "a");
            fprintf(f_s_coeffs_guessed, "\n*****Guessed Secret %d*****\n",no_attacks);

            for(int i = 0;i < NEWHOPE_N;i++)
            {
                fprintf(f_s_coeffs_guessed, "%d, ",guessed_s_coeffs[i]);
            }
            fprintf(f_s_coeffs_guessed, "\n");
            fclose(f_s_coeffs_guessed);
        }
        trace_complexity = (float)trace_complexity/total_attacks;
        success_rate = (float)success_rate/total_attacks;

        // Calculating average actual trace requirement and success rate of the attack....

        printf("Actual Avg. Trace requirement: %f, Success_Rate: %f",trace_complexity,success_rate);
    }


  return 0;
}
