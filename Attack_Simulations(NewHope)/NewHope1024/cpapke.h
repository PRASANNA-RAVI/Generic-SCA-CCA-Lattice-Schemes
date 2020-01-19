#ifndef INDCPA_H
#define INDCPA_H

void cpapke_keypair(unsigned char *pk,
                    unsigned char *sk);

void cpapke_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins, int count, int choice_u, int choice_v_1, int choice_v_2, int choice_v_3, int choice_v_4);

int cpapke_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

#endif
