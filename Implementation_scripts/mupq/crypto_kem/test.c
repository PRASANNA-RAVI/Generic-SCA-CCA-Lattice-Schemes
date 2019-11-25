#include "api.h"
#include "randombytes.h"
#include "hal.h"
#include <libopencm3/stm32/gpio.h>
#include <string.h>

#define NTESTS 1

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x####y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec)
/* allocate a bit more for all keys and messages and
 * make sure it is not touched by the implementations.
 */
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

static int test_keys(void)
{
  unsigned char key_a[MUPQ_CRYPTO_BYTES+16], key_b[MUPQ_CRYPTO_BYTES+16];
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES+16];
  unsigned char sendb[MUPQ_CRYPTO_CIPHERTEXTBYTES+16];
  unsigned char sk_a[MUPQ_CRYPTO_SECRETKEYBYTES+16];
  unsigned char recv_byte_start;

  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);

  int count = 0;

  MUPQ_crypto_kem_keypair(pk+8, sk_a+8);

  while(1)
  {
      recv_USART_bytes(&recv_byte_start,1);

      if(recv_byte_start == 'S')     // This is to collect attack traces...
      {
          MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8, count, 0);
          MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

          hal_send_str("Z");

          if(memcmp(key_a+8, key_b+8, MUPQ_CRYPTO_BYTES))
          {
            // hal_send_str("Y");
          }

          else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
                  check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
                  check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
                  check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
                  check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
          {
            // hal_send_str("ERROR canary overwritten\n");
          }
          else
          {
            // hal_send_str("Z\n");
          }
          count = count+1;
      }

      if(recv_byte_start == 'O')       // This is to collect profiling traces for m = 0
      {
          count = 0;
          MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8, count, 1);
          MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

          hal_send_str("Z");

          if(memcmp(key_a+8, key_b+8, MUPQ_CRYPTO_BYTES))
          {
            // hal_send_str("Y");
          }

          else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
                  check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
                  check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
                  check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
                  check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
          {
            // hal_send_str("ERROR canary overwritten\n");
          }
          else
          {
            // hal_send_str("Z\n");
          }
      }

      if(recv_byte_start == 'X')        // This is to collect profiling traces for m = 1
      {
          count = 0;
          MUPQ_crypto_kem_enc(sendb+8, key_b+8, pk+8, count, 2);
          MUPQ_crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

          hal_send_str("Z");

          if(memcmp(key_a+8, key_b+8, MUPQ_CRYPTO_BYTES))
          {
            // hal_send_str("Y");
          }

          else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
                  check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
                  check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
                  check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
                  check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
          {
            // hal_send_str("ERROR canary overwritten\n");
          }
          else
          {
            // hal_send_str("Z\n");
          }
      }

  }

  return 0;
}

int main(void)
{
  hal_setup(CLOCK_BENCHMARK);

  unsigned char recv_byte_start;

  test_keys();

  return 0;
}
