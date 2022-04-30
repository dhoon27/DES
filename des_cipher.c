
#define DEBUG 1
#ifdef DEBUG
#include <stdio.h>
#define PRINT printf
#endif
#include <string.h>
#include "des_cipher.h"
#include "des_param.h"
#include "des_pad.h"
#include "utils.h"

void key_schedule(uint64_t key, uint64_t* sub_key)
{
    // key permutation with PC1
    key = permute(PC1, sizeof(PC1) / sizeof(PC1[0]), key, 64);

    // split into 28-bit left and right (c and d) pairs
    uint32_t C = (uint32_t)((key >> 28) & 0x000000000fffffff);
    uint32_t D = (uint32_t)(key & 0x000000000fffffff);

    for (uint8_t i = 0; i < ROUND; i++)
    {
        switch ((int)(LEFT_SHIFTS[i]))
        {
        case 1:
        { // left shift 1 bit
            C = ((C << 1) & 0x0FFFFFFF) | (C >> 27);
            D = ((D << 1) & 0x0FFFFFFF) | (D >> 27);
            break;
        }
        case 2:
        { // left shift 2 bit
            C = ((C << 2) & 0x0FFFFFFF) | (C >> 26);
            D = ((D << 2) & 0x0FFFFFFF) | (D >> 26);
            break;
        }
        }
        // join C, D
        uint64_t CD = (((uint64_t)C) << 28) | (uint64_t)D;
        // PC2 permutation into 48 bits
        sub_key[i] = permute(PC2, sizeof(PC2) / sizeof(PC2[0]), CD, 56);
    }
}

void des_cbc_enc(unsigned char *msg, unsigned char *cipher, uint64_t *sub_key, uint64_t iv)
{
    uint64_t len = strlen(msg);
    uint64_t buffer = 0;
    uint32_t c_idx = 0;
    // start CBC mode
    uint64_t c_prev = iv;
    for (uint64_t i = 0; i < len / 8; ++i)
    {
        buffer = 0;
        uint64_t tmp_msg;
        for(uint64_t idx=i*8; idx < i*8+8; idx++){
            buffer <<= 8ull;
            buffer |= msg[idx];
        }
        uint64_t p_curr = buffer;
        c_prev = des(sub_key, p_curr ^ c_prev, ENC);
        PRINT("c_prev = %#llX\n", c_prev);
        
        unsigned char buf[8] = {0,};
        for(uint64_t idx=0;idx<8;idx++){
            buf[7-idx] = (unsigned char)((c_prev & (0xFFull << idx * 8ull)) >> idx * 8ull);
            PRINT("buf = 0x%02X\n", buf[7-idx]);
        }
        for (uint64_t idx = 0; idx < 8; idx++){
            *(cipher + c_idx) = buf[idx];
            c_idx++;
        }
    }
    

    // last block: perform PKCS5 Padding if necessary
    uint64_t padlen = get_pad_length(len);
    if (padlen == 8)
    {
        uint64_t p_curr = 0x0808080808080808;
        c_prev = des(sub_key, p_curr ^ c_prev, ENC);
        PRINT("c_prev = %#llX\n", c_prev);
        
        unsigned char buf[8] = {0,};
        for(uint64_t idx=0;idx<8;idx++){
            buf[7-idx] = (unsigned char)((c_prev & (0xFFull << idx * 8ull)) >> idx * 8ull);
            PRINT("buf = 0x%02X\n", buf[7-idx]);
        }
        for (uint64_t idx = 0; idx < 8; idx++){
            *(cipher + c_idx) = buf[idx];
            c_idx++;
        }
    }
    else
    {
        buffer = 0;
        for (int idx = (len / 8) * 8; idx < (len / 8) * 8 + (len % 8); idx++)
        {
            buffer <<= 8;
            buffer |= msg[idx];
        }
        buffer <<= 8*padlen;
        uint64_t p_curr = buffer;
        p_curr = pad_with_length(p_curr, padlen);
        c_prev = des(sub_key, p_curr ^ c_prev, ENC);
        PRINT("c_prev = %#llX\n", c_prev);
        
        unsigned char buf[8] = {0,};
        for(uint64_t idx=0;idx<8;idx++){
            buf[7-idx] = (unsigned char)((c_prev & (0xFFull << idx * 8ull)) >> idx * 8ull);
            PRINT("buf = 0x%02X\n", buf[7-idx]);
        }
        for (uint64_t idx = 0; idx < 8; idx++){
            *(cipher + c_idx) = buf[idx];
            c_idx++;
        }
    }
    for(int i=0; i < c_idx; ++i){
        PRINT("Cipher = 0x%0X\n", *(cipher + i));
    }
}

void des_cbc_dec(unsigned char *msg, unsigned char *ans, uint64_t *sub_key, uint64_t iv)
{
    uint64_t len = strlen(msg);
    uint64_t buffer = 0;
    uint32_t a_idx = 0;
   
    uint64_t c_prev = iv;
    uint64_t i;
    for (i = 0; i < (len / 8) -1; ++i)
    {
        buffer = 0;
        for(uint64_t idx=i*8; idx < i*8+8; idx++){
            buffer <<= 8ull;
            buffer |= msg[idx];
        }
        uint64_t p_curr = buffer;
        uint64_t res = des(sub_key, p_curr, DEC) ^c_prev;
        
        PRINT("res = %#llX\n", res);
        
        unsigned char buf[8] = {0,};
        for(uint64_t idx=0;idx<8;idx++){
            buf[7-idx] = (unsigned char)((res & (0xFFull << idx * 8ull)) >> idx * 8ull);
            PRINT("buf = 0x%02X\n", buf[7-idx]);
        }
        for (uint64_t idx = 0; idx < 8; idx++){
            *(ans + a_idx) = buf[idx];
            a_idx++;
        }
        c_prev = p_curr;
    }
    
    buffer = 0;
    for(uint64_t idx=i*8; idx < i*8+8; idx++){
        buffer <<= 8ull;
        buffer |= msg[idx];
    }
    uint64_t p_curr = buffer;
    uint64_t res = des(sub_key, p_curr, DEC) ^c_prev;
        
    PRINT("res = %#llX\n", res);
    // last byte: pad value
    int padlen = (res & 0xFF); 

    if (padlen < 8) {
        res = remove_pad(res, padlen);
        PRINT("res = %#llX\n", res);
        
        unsigned char buf[8] = {0,};
        for(uint64_t idx=0;idx<8;idx++){
            buf[7-idx] = (unsigned char)((res & (0xFFull << idx * 8ull)) >> idx * 8ull);
            PRINT("buf = 0x%02X\n", buf[7-idx]);
        }
        for (uint64_t idx = 0; idx < 8; idx++){
            *(ans + a_idx) = buf[idx];
            a_idx++;
        }
    }

    for(int i=0; i < a_idx; ++i){
        PRINT("Ans = 0x%0X\n", *(ans + i));
    }
}

uint64_t ip(uint64_t M)
{
    return permute(IP, sizeof(IP) / sizeof(IP[0]), M, 64);
}

uint64_t fp(uint64_t M)
{
    return permute(FP, sizeof(FP) / sizeof(FP[0]), M, 64);
}

uint64_t Expand(uint32_t R)
{
    return permute(E, sizeof(E) / sizeof(E[0]), R, 32);
}

char S(int sbox, uint8_t input)
{
    char row = (char)(((input & 0x20) >> 4) | (input & 0x01));
    char col = (char)((input & 0x1E) >> 1);
    return SBOXMAP[sbox][16 * row + col];
}

uint32_t F(uint64_t K, uint32_t R)
{
    // expanded R from 32 bits to 48 bits, using the selection table
    uint64_t e = Expand(R);
    // XORed the result with key K
    e ^= K;

    // apply S-Boxes function and permute from 48 bit to 32 bit
    uint32_t output = 0;
    for (int i = 0; i < 8; ++i)
    {
        output <<= 4;
        output |= (uint32_t)S(i, (uint8_t)((e & 0xFC0000000000) >> 42));
        e <<= 6;
    }

    // apply a permutation P of the S-box output to obtain the final value of f:
    // P yields a 32-bit output from a 32-bit input by permuting the bits of the input block
    return (uint32_t)permute(P, sizeof(P) / sizeof(P[0]), output, 32);
}
uint64_t des(uint64_t* sub_key, uint64_t M, int enc)
{

    // 1. InitialPermutation(M);
    M = ip(M);

    // divide permuted block IP into a left half L0 of 32 bits,
    // and a right half R0 of 32 bits.
    uint32_t L = (uint32_t)(M >> 32) & 0x0FFFFFFFF;
    uint32_t R = (uint32_t)(M & 0x0FFFFFFFF);

    // 2. subkey generation:
    // moved into main method

    // 3. start substitution
    for (int i = 0; i < ROUND; ++i)
    {
        uint32_t oldL = L;
        // in case of decryption: reverse order in which sub_key are applied
        uint64_t subkey = enc ? sub_key[i] : sub_key[ROUND - i - 1];
        L = R;                   // LEi = REi-1;
        R = oldL ^ F(subkey, R); // REi = LEi-1 XOR F(Ki,REi-1);
    }

    // 4. reverse the order of the two blocks into the 64-bit block
    // swap(LE16,RE16); from L16R16 to R16L16
    M = (((uint64_t)R) << 32) | (uint64_t)L;

    // 5. apply a final permutation
    // C = IP-1(LE16||RE16);
    return fp(M); // 64 bits;
}