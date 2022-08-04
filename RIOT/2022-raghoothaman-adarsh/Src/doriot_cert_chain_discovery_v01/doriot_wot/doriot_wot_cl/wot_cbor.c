/**
 * @file wot_cbor.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-02-16
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "wot_cbor.h"
#include "wot_list.h"
#include "wot_key.h"

#define ENABLE_DEBUG 0
#include "debug.h"

#ifdef CONFIG_WOT_CL_COMMON_NAME
int wot_get_cbor_certificate(uint8_t *buf)
{
    CborEncoder encoder;
    CborEncoder array_encoder;
    uint8_t cbor_buf[CBOR_BUFSIZE];
    uint8_t cbor_len = 0;
    uint8_t pubkey[PUB_KEY_SIZE];
    char *common_name = "";

    DEBUG("\n\ncreating CBOR cert\n");
    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    //TODO Solve stack smashing when name_len > 5 ?
    common_name = strndup(CONFIG_WOT_CL_COMMON_NAME, strlen(CONFIG_WOT_CL_COMMON_NAME));
    //memcpy(common_name,CONFIG_WOT_CL_COMMON_NAME,strlen(CONFIG_WOT_CL_COMMON_NAME));
    /*memcpy(pubkey, cli_ecdsa_pub_key_x, 32);
    memcpy(pubkey + 32, cli_ecdsa_pub_key_y, 32);*/
    memcpy(pubkey,wot_public_key,PUB_KEY_SIZE);

    /*encode common name*/
    cbor_encode_text_stringz(&array_encoder, common_name );
    /*encode public key*/
    cbor_encode_byte_string(&array_encoder, pubkey, PUB_KEY_SIZE);
    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf);
    memcpy(buf, cbor_buf, cbor_len);

    DEBUG("cbor cert size:%d\n", cbor_len);
    printf("c509 cert:");
    for (int i = 0; i < cbor_len; i++) {
        printf("%02X", cbor_buf[i]);
    }
    printf("\n");
    return cbor_len;
}
#endif /*CONFIG_WOT_CL_COMMON_NAME*/



CborError wot_parse_cbor_cert(uint8_t *payload, uint16_t payload_len)
{
    CborParser parser;
    CborValue it;
    uint8_t pub_buf[PUB_KEY_SIZE];
    char *common_name = "";
    size_t common_name_len = 0;


    CborError err = cbor_parser_init(payload, payload_len, 0, &parser, &it);

    if (err) {
        printf("error parsing cbor certificate....\n");
        return err;
    }
    CborType type = cbor_value_get_type(&it);
    if (type == CborArrayType) {
        CborValue recursed;
        err = cbor_value_enter_container(&it, &recursed);
        if (err) {
            return err;
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborTextStringType) {
            cbor_value_get_string_length(&recursed, &common_name_len);
            err = cbor_value_copy_text_string(&recursed, common_name, &common_name_len, &recursed);
            if (err) {
                return err;
            }
            printf("common name:%.*s\n", common_name_len, common_name);
        }
        //cbor_value_advance(&recursed);
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            size_t len = 0;
            cbor_value_get_string_length(&recursed, &len);
            if (len != PUB_KEY_SIZE) {
                printf("received pub key length invalid");
            }
            memset(pub_buf, 0, PUB_KEY_SIZE);
            err = cbor_value_copy_byte_string(&recursed, pub_buf, &len, &recursed);
            if (err) {
                return err;
            }
            printf("public key:");
            for (int i = 0; i < (int)len; i++) {
                printf("%02X", pub_buf[i]);
            }
            printf("\n");
        }
    }
    //wot_cert_t *node = wot_cert_add(common_name, (int)common_name_len, pub_buf);
    wot_cert_t *node = wot_cert_add(common_name, strlen(common_name), pub_buf);
    DEBUG("stored node name:%s\n", node->name);
    return CborNoError;
}
