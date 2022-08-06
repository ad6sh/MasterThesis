/**
 * @file wot_key.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-03-26
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <stdio.h>
#include <string.h>
#include "wot_key.h"


static void _print_hex(char *str, uint8_t *buf, unsigned int size)
{
    printf("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        printf("%02X ", (unsigned)buf[i]);
    }
    puts("\n\n");
}

wot_credentials_t credentials_module = { KEYS__NOT_STORED, { 0 }, { 0 }, { 0 } };

int wot_provision_keys(wot_credentials_t *keys)
{
    credentials_module.status = KEYS_STORED;
    memcpy((credentials_module.private_key), (keys->private_key), PVT_KEY_SIZE);
    memcpy((credentials_module.public_key), (keys->public_key), PUB_KEY_SIZE);
    memcpy((credentials_module.psk_key), (keys->psk_key), PSK_KEY_LEN);

    /*printf("provided key to the module\n");
       printf("status:%d\n",key_pair_module.status);
       _print_hex("private :", key_pair_module.private_key, PVT_KEY_SIZE);
       _print_hex("public :", key_pair_module.public_key, PUB_KEY_SIZE);*/
    return 0;
}