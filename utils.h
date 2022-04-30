#ifndef __UTILS__
#define __UTILS__

#define uint8_t unsigned char
#define uint32_t unsigned int
#define uint64_t unsigned long long

void get_msg(char*, int);
uint64_t permute(const char *, uint8_t, uint64_t, uint8_t);

#endif