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


int wot_find_cert(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    wot_cert_t *node = wot_cert_find(&head, argv[1]);
    if (node == NULL) {
        printf("certificate not found for :%s\n", argv[1]);
        return 1;
    }
    else {
        printf("certificate found for :%s\n", node->name);
    }
    return 0;
}
