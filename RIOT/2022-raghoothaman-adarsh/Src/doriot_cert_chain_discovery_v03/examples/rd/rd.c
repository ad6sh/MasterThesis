#include <stdio.h>
#include <stdlib.h>
#include "doriot_wot_rd.h"

extern uint32_t c509_start_time[100];
extern uint32_t c509_end_time[100];
extern uint32_t crypto_start_time[100];
extern uint32_t crypto_end_time[100];
extern uint32_t count_lkup;



int print_time(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /*printf("lookup count:%ld\n", count_lkup);

    for (uint32_t i = 0; i < count_lkup; i++) {
        printf("process_time:%ld\n", c509_end_time[i] - c509_start_time[i]);
        printf("crypto_time:%ld\n", crypto_end_time[i] - crypto_start_time[i]);
    }
    count_lkup = 0; */
    return 0;
}


static int _print_usage_rd(char **argv)
{
    printf("usage: %s start\n", argv[0]);
    return 1;
}


int rd_start_cmd_app(int argc, char **argv)
{

    (void)argc;
    (void)argv;
    if (argc == 1) {
        return _print_usage_rd(argv);
    }

    if (strcmp(argv[1], "-help") == 0) {
        return _print_usage_rd(argv);
    }

    else if ((strcmp(argv[1], "start") == 0)) {
        if (argc != 2) {
            return _print_usage_rd(argv);
        }
        else {
            wot_rd_start();
        }

    }
    else {
        return _print_usage_rd(argv);
    }

    return 0;
}


static void _print_hex(char *str, uint8_t *buf, unsigned int size)
{
    printf("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        printf("%02X ", (unsigned)buf[i]);
    }
    printf("\n\n");
}

int find_cert_cmd_app(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (argc != 2) {
        printf("usage :find common_name\n");
        return 1;
    }

    wot_cert_t *node = wot_cert_get(argv[1]);
    if (node == NULL) {
        printf("certificate not found for :%s\n", argv[1]);
        return 1;
    }
    else {
        printf("size of cert struct:%d\n",sizeof(wot_cert_t));
        printf("size of name:%d\n",sizeof(node->name));
        printf("size of pub:%d\n",sizeof(node->pubkey));
        printf("size of listnode:%d\n",sizeof(node->next));
        printf("certificate found for :%s\n", node->name);
        _print_hex("public key :", node->pubkey, (unsigned int)PUB_KEY_SIZE);

    }
    return 0;
}


int delete_cert_cmd_app(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (argc != 2) {
        printf("usage :wotd common_name\n");
        return 1;
    }
    wot_cert_t *node = wot_cert_del(argv[1]);
    if (node == NULL) {
        printf("certificate not found for :%s\n", argv[1]);
        return 1;
    }
    else {
        printf("certificate deleted :%s\n", node->name);
    }
    return 0;
}


static unsigned char test_pub_key[] = {
    0x6F, 0x0B, 0xD3, 0xE6, 0x92, 0x58, 0xB4, 0x38, 0x82, 0xC6, 0xAE, 0x0B, 0xE1, 0x9F, 0x50, 0x4A,
    0xB2, 0x40, 0x6D, 0xE3, 0xCB, 0xC2, 0x93, 0x27, 0x4E, 0x59, 0x37, 0x36, 0xC0, 0x80, 0xC1, 0x73,
    0x06, 0xDE, 0x7C, 0x6E, 0x4E, 0xC8, 0x6B, 0xD5, 0x92, 0xDE, 0x98, 0x09, 0x1B, 0x06, 0x2A, 0x8C,
    0x68, 0x6F, 0x9E, 0xAF, 0x74, 0x47, 0x58, 0x86, 0xD8, 0x2C, 0x17, 0x68, 0xF4, 0x69, 0xB5, 0x0F
};

#define TEST_NAME "charlie"

int add_cert_cmd_app(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    if (argc != 3) {
        printf("Enter count,name!!\n");
        return 1;
    }

    int count = atoi(argv[1]);
    printf("count:%d\n", count);

    for (int i = 0; i < count; i++) {
        wot_cert_t *node = wot_cert_add(argv[2], strlen(argv[2]), test_pub_key);
    }
    printf("added %d certs to list\n", count);

    return 0;
}
