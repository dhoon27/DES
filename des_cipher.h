#ifndef __CIPHER__
#define __CIPHER__

#include "utils.h"

void key_schedule(uint64_t, uint64_t*);
void des_cbc_enc(unsigned char *, unsigned char *, uint64_t *, uint64_t);
void des_cbc_dec(unsigned char *, unsigned char *, uint64_t *, uint64_t);

uint64_t ip(uint64_t);
uint64_t fp(uint64_t);
// expand R from 32 bits to 48 bits
uint64_t Expand(uint32_t);

// Given 6 bit input, returns 4 bit specified in S-box table
char S(int, uint8_t);

// output: 32 bit
uint32_t F(uint64_t, uint32_t);
uint64_t des(uint64_t *, uint64_t, int);

#endif