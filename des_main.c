#include <stdio.h>
#include "des_param.h"
#include "des_cipher.h"
#include "utils.h"

unsigned char msg[MAX_MSG];
unsigned char cipher[MAX_MSG];
unsigned char answer[MAX_MSG];
// int IV = 0xB15;

uint64_t IV = 0xB1502DC28E930F51;
uint64_t key = 0xFB20E752292B0D;
uint64_t sub_key[ROUND];

int main()
{
    get_msg(msg, MAX_MSG);
    printf("Plain Text: %s\n",msg);
    key_schedule(key, sub_key);
    printf("key: %#llx\n", key);
    for(int i=0;i<ROUND;i++)
    {
        printf("ROUND %d key: %#llx\n",i, sub_key[i]);
    }
    des_cbc_enc(msg, cipher, sub_key, IV);
    printf("ENC Text: %s\n", cipher);
    des_cbc_dec(cipher, answer, sub_key, IV);
    printf("DEC Text: %s\n", answer);

    return 0;
}