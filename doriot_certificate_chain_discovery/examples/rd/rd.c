#include <stdio.h>
#include <stdlib.h>
#include "doriot_wot_rd.h"

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
