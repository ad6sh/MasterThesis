/**
 * @file wot_cbor.h
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief 
 * @version 0.1
 * @date 2022-02-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef WOT_CBOR_H
#define WOT_CBOR_H

#include "cbor.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBOR_BUFSIZE 256
#define NAME_MAX_LEN 16

/**
 * @brief print hex
 * 
 * @param str 
 * @param vli 
 * @param size 
 */
void print_hex(char *str, uint8_t *vli, unsigned int size);

/**
 * @brief Get the cbor certificate object
 *
 * @param buf
 * @param type
 */
int wot_get_cbor_certificate_rd(uint8_t *buf);


/**
 * @brief function to parse cbor certificate
 * 
 * @param payload 
 * @param payload_len 
 * @return CborError 
 */
CborError wot_parse_cbor_cert_client(uint8_t *payload, uint16_t payload_len);


#ifdef __cplusplus
}
#endif

#endif /* WOT_CBOR_H */
