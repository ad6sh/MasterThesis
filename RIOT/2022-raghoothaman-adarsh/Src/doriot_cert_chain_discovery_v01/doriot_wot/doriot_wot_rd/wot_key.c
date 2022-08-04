#include "wot_key.h"
#include <string.h>

uint8_t wot_public_key[PUB_KEY_SIZE]={0};

int wot_provision_pub_key(uint8_t *pub_key)
{
    memcpy(wot_public_key,pub_key,PUB_KEY_SIZE);
    return 0;
}
