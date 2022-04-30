#ifndef __PAD__
#define __PAD__
#include "utils.h"

uint64_t get_pad_length(uint64_t);

// pad pad_len bytes with value pad_len to end of data
uint64_t pad_with_length(uint64_t, uint64_t);

// clear pad_len bytes from end of data
uint64_t remove_pad(uint64_t, uint64_t);

#endif