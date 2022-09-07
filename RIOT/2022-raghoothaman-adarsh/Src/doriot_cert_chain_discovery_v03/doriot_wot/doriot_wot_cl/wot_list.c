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

    if (node != NULL) {
        memcpy(&node->name, name, name_len);
        memcpy(&node->pubkey, pubkey, PUB_KEY_SIZE);
        list_add(&head, &node->next);
        return node;
    }
    return NULL;
}


bool wot_node_exists(char *name)
{
    for (list_node_t *n = head.next; n; n = n->next) {
        wot_cert_t *node = container_of(n, wot_cert_t, next);
        if (strncmp(node->name, name, sizeof(node->name)) == 0) {
            return true;
        }
    }
    return false;
}


wot_cert_t *wot_cert_get(char *name)
{
    for (list_node_t *n = head.next; n; n = n->next) {
        wot_cert_t *node = container_of(n, wot_cert_t, next);
        if (strncmp(node->name, name, sizeof(node->name)) == 0) {
            return node;
        }
    }
    return NULL;
}


wot_cert_t *wot_cert_del(char *name)
{
    for (list_node_t *n = head.next; n; n = n->next) {
        wot_cert_t *node = container_of(n, wot_cert_t, next);
        if (strncmp(node->name, name, sizeof(node->name)) == 0) {
            list_node_t *deleted_node = list_remove(&head, &node->next);
            if (deleted_node == NULL) {
                return NULL;
            }
            else {
                return node;
            }
        }
    }
    return NULL;
}