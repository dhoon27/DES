#include <stdio.h>
#include "utils.h"

void get_msg(char* msg, int length)
{
    FILE* fp = fopen("input.txt","r");
    fgets(msg, length, fp);
    fclose(fp);
}

uint64_t permute(const char *table, uint8_t table_len, uint64_t input, uint8_t input_len)
{
    uint64_t res = 0;
    for (uint8_t i = 0; i < table_len; i++)
    {
        res = (res << 1) | ((input >> (input_len - table[i])) & 0x01);
    }
    return res;
}