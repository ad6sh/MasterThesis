#ifndef WOT_LIST_H
#define WOT_LIST_H

#include <string.h>
#include <stdint.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PUB_KEY_SIZE 64
#define COMMON_NAME_MAX_LEN 16


typedef struct {
    list_node_t next;
    char name[COMMON_NAME_MAX_LEN];
    uint8_t pubkey[PUB_KEY_SIZE];
}wot_cert_t;

/**
 * @brief function to add certificate to list 
 * 
 * @param name 
 * @param name_len 
 * @param pubkey 
 * @return wot_cert_t* 
 */
wot_cert_t *wot_cert_add(char *name,int name_len,uint8_t *pubkey);


#ifdef __cplusplus
}
#endif

#endif /* WOT_LIST_H */
