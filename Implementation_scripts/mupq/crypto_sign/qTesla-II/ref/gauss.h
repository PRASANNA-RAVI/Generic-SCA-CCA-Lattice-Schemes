#ifndef __GAUSS_H
#define __GAUSS_H

#include <stdint.h>
#include "params.h"
#include "config.h"
#include "poly.h"

#define CHUNK_SIZE 256   // Fix chunk size for sampling

void sample_gauss_poly(poly z, const unsigned char *seed, int nonce);

#endif
