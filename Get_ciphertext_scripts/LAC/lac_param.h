//#define TEST_ROW_ERROR_RATE
//security level
#define LAC128
//modulus
#define Q 251
#define BIG_Q 257024//1024*Q

#if defined(LAC128)
//parameter for LAC_LIGHT
#define STRENGTH "LAC128"
#define DIM_N 512
#define SEED_LEN 32
#define PK_LEN 544 //N+SEED_LEN
#define MESSAGE_LEN 32
#define CIPHER_LEN 736//N+C2_VEC_NUM/2=708
#define C2_VEC_NUM 448//(DATA_LEN+ECC_LEN)*8
#define PSI//secret and error distribution
#define HASH_TYPE "SHA256"
#endif

#if defined(LAC192)
//parameter for LAC_STANDARD
#define STRENGTH "LAC192"
#define DIM_N 1024
#define SEED_LEN 32
#define PK_LEN 1056//N+SEED_LEN
#define MESSAGE_LEN 32
#define CIPHER_LEN 1248//N+C2_VEC_NUM/2=1183
#define C2_VEC_NUM 448//(DATA_LEN+ECC_LEN)*8
#define PSI_SQUARE//secret and error distribution
#define HASH_TYPE "SHA256"
#endif

#if defined(LAC256)
//parameter for LAC_HIGH
#define STRENGTH "LAC256"
#define DIM_N 1024
#define SEED_LEN 32
#define PK_LEN 1056//(N+SEED_LEN)
#define MESSAGE_LEN 32
#define CIPHER_LEN 1472//(N+C2_VEC_NUM/2)
#define C2_VEC_NUM 896//(DATA_LEN+ECC_LEN)*8
#define PSI//secret and error distribution
#define HASH_TYPE "SHA256"
#endif
