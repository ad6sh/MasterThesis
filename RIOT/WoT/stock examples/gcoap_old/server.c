/*
 * Copyright (c) 2015-2017 Ken Bannister. All rights reserved.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       gcoap CLI support
 *
 * @author      Ken Bannister <kb2ma@runbox.com>
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fmt.h"
#include "net/gcoap.h"
#include "net/utils.h"
#include "od.h"

#include "gcoap_example.h"

#include "cbor.h"

#define ENABLE_DEBUG 0
#include "debug.h"

#if IS_USED(MODULE_GCOAP_DTLS)
#include "net/credman.h"
#include "net/dsm.h"
#include "tinydtls_keys.h"

/* Example credential tag for credman. Tag together with the credential type needs to be unique. */
#define GCOAP_DTLS_CREDENTIAL_TAG 10

static const uint8_t psk_id_0[] = PSK_DEFAULT_IDENTITY;
static const uint8_t psk_key_0[] = PSK_DEFAULT_KEY;
static const credman_credential_t credential = {
    .type = CREDMAN_TYPE_PSK,
    .tag = GCOAP_DTLS_CREDENTIAL_TAG,
    .params = {
        .psk = {
            .key = { .s = psk_key_0, .len = sizeof(psk_key_0) - 1, },
            .id = { .s = psk_id_0, .len = sizeof(psk_id_0) - 1, },
        }
    },
};
#endif

static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context);
static ssize_t _rd_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
static ssize_t _cli_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
static CborError _parse_cbor_rd(CborValue *it);



/* CoAP resources. Must be sorted by path (ASCII order). */
static const coap_resource_t _resources[] = {
    { "/cli/cert", COAP_PUT, _cli_cert_handler, NULL },
    { "/rd/cert", COAP_GET, _rd_cert_handler, NULL },
};

static const char *_link_params[] = {
    ";ct=0;rt=\"count\";obs",
    NULL
};

static gcoap_listener_t _listener = {
    &_resources[0],
    ARRAY_SIZE(_resources),
    _encode_link,
    NULL,
    NULL
};


/* Adds link format params to resource list */
static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context)
{
    ssize_t res = gcoap_encode_link(resource, buf, maxlen, context);

    if (res > 0) {
        if (_link_params[context->link_pos]
            && (strlen(_link_params[context->link_pos]) < (maxlen - res))) {
            if (buf) {
                memcpy(buf + res, _link_params[context->link_pos],
                       strlen(_link_params[context->link_pos]));
            }
            return res + strlen(_link_params[context->link_pos]);
        }
    }

    return res;
}



static ssize_t _cli_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;

    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    switch (method_flag) {

    case COAP_PUT:
        /* convert the payload to an integer and update the internal
           value */
        if (pdu->payload_len) {
            unsigned content_type = coap_get_content_type(pdu);
            if (content_type == COAP_FORMAT_CBOR) {

                puts("\nreceived client CBOR cert");
                printf("CBOR cert size:%d\n", pdu->payload_len);
                printf("c509 cert:");
                for (int i = 0; i < pdu->payload_len; i++) {
                    printf("%02X", pdu->payload[i]);
                }
                printf("\n");

                CborParser parser;
                CborValue it;
                CborError err = cbor_parser_init(pdu->payload, pdu->payload_len, 0, &parser, &it);
                if (!err) {
                    puts("parsing client certificate....");
                }
                err = _parse_cbor_rd(&it);

                if (err) {
                    printf("CBOR parsing failure\n");
                    return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);

                }
            }
            //char payload[6] = { 0 };
            //memcpy(payload, (char *)pdu->payload, pdu->payload_len);
            return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
        }
        else {
            return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
        }
    }

    return 0;
}



static ssize_t _rd_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    uint8_t cbor_buf[256];
    CborEncoder encoder;
    CborEncoder array_encoder;
    uint8_t cbor_len = 0;
    uint8_t rd_pubkey[64];

    printf("received certificate request from client\n");

    cbor_encoder_init(&encoder, cbor_buf, sizeof(cbor_buf), 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    printf("encoding common name and publickey to cbor...\n");
    /*encode common name of resource directory */
    cbor_encode_text_stringz(&array_encoder, "rd1cn" );
    memcpy(rd_pubkey, ecdsa_pub_key_x, 32);
    memcpy(rd_pubkey + 32, ecdsa_pub_key_y, 32);
    /*encode public key of resource directory */
    cbor_encode_byte_string(&array_encoder, rd_pubkey, 64);

    cbor_encoder_close_container(&encoder, &array_encoder);

    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf);
    printf("cbor buffer size:%d\n", cbor_len);
    printf("rd c509 cert:");
    for (int i = 0; i < cbor_len; i++) {
        printf("%02X", cbor_buf[i]);
    }
    printf("\n");

    (void)ctx;
    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_CBOR);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* write the cbor cert in the response buffer */
    if (pdu->payload_len >= cbor_len) {
        memcpy(pdu->payload, cbor_buf, cbor_len);
        printf("sent rd certificate to client\n");
        return resp_len + cbor_len;
    }
    else {
        puts("gcoap_cli: msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
}


void server_init(void)
{
#if IS_USED(MODULE_GCOAP_DTLS)
    int res = credman_add(&credential);
    if (res < 0 && res != CREDMAN_EXIST) {
        /* ignore duplicate credentials */
        printf("gcoap: cannot add credential to system: %d\n", res);
        return;
    }
    sock_dtls_t *gcoap_sock_dtls = gcoap_get_sock_dtls();
    res = sock_dtls_add_credential(gcoap_sock_dtls, GCOAP_DTLS_CREDENTIAL_TAG);
    if (res < 0) {
        printf("gcoap: cannot add credential to DTLS sock: %d\n", res);
    }
#endif

    gcoap_register_listener(&_listener);
}

static CborError _parse_cbor_rd(CborValue *it)
{

    CborError err;
    CborType type = cbor_value_get_type(it);

    if (type == CborArrayType) {
        //printf("CBOR array found in reply\n");
        CborValue recursed;
        err = cbor_value_enter_container(it, &recursed);
        if (err) {
            return err;
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborTextStringType) {
            //printf("Found text string\n");
            size_t n = 0;
            cbor_value_get_string_length(&recursed, &n);
            //printf("text string length:%d\n", n);
            char *buf = "";
            err = cbor_value_copy_text_string(&recursed, buf, &n, &recursed);
            if (err) {
                return err;     // parse error
            }
            printf("client common name:%.*s\n", n, buf);
            //free(buf);

        }
        //cbor_value_advance(&recursed);
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            //printf("Found byte string\n");
            size_t len = 0;
            cbor_value_get_string_length(&recursed, &len);
            //printf("byte string length:%d\n", len);
            uint8_t pub_buf[len];
            memset(pub_buf, 0, len);
            err = cbor_value_copy_byte_string(&recursed, pub_buf, &len, &recursed);
            if (err) {
                return err;     // parse error
            }
            printf("client public key:");
            for (int i = 0; i < (int)len; i++) {
                printf("%02X", pub_buf[i]);
            }

        }

    }
    return CborNoError;
}
