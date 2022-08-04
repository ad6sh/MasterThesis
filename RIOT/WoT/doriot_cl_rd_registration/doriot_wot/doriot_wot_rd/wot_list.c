/**
 * @file wot_list.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief 
 * @version 0.1
 * @date 2022-03-26
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include "wot_list.h"
#include <stdlib.h>
#include <stdio.h>
#include "kernel_defines.h"


//static list_node_t head = { .next = NULL };
static list_node_t head;


wot_cert_t *wot_cert_add(char *name, int name_len, uint8_t *pubkey)
{
    wot_cert_t *node = (wot_cert_t *)calloc(1, sizeof(wot_cert_t));
    if(node != NULL)
    {
    memcpy(&node->name, name, name_len);
    memcpy(&node->pubkey, pubkey, PUB_KEY_SIZE);
    list_add(&head, &node->next);
    return node;
    }
    return NULL;
}

wot_cert_t *wot_cert_find(list_node_t *head, char *name)
{
    for (list_node_t *n = head->next; n; n = n->next) {
        wot_cert_t *node = container_of(n, wot_cert_t, next);
        if (strncmp(node->name, name, sizeof(node->name)) == 0) {
            return node;
        }
    }
    return NULL;
}


void _print_hex(char *str, uint8_t *buf, unsigned int size)
{
    printf("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        printf("%02X ", (unsigned)buf[i]);
    }
    printf("\n\n");
}


int wot_find_cert(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (argc != 2) {
        printf("usage :wotf common_name\n");
        return 1;
    }
    if (head.next == NULL) {
        printf("No nodes stored in the list\n");
        return 1;
    }
    wot_cert_t *node = wot_cert_find(&head, argv[1]);
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

