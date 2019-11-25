#include <stdint.h>

#ifndef HAL_H
#define HAL_H

enum clock_mode {
    CLOCK_FAST,
    CLOCK_BENCHMARK
};

void hal_setup(const enum clock_mode clock);
void hal_send_str(const char* in);
uint64_t hal_get_time(void);
void send_USART_bytes(const unsigned char* in, int n);
void recv_USART_bytes(unsigned char* out, int n);
void send_USART_str(const char* in);

#endif
