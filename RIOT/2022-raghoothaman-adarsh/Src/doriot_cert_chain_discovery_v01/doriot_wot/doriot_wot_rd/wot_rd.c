/**
 * @file server.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-02-16
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fmt.h"
#include "net/gcoap.h"
#include "net/utils.h"
#include "od.h"

#include "wot_cbor.h"
#include "wot_auth.h"

#define ENABLE_DEBUG 1
#include "debug.h"

static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context);
static ssize_t _rd_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
static ssize_t _cli_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);

/* CoAP resources. Must be sorted by path (ASCII order). */
#ifdef CONFIG_WOT_CLIENT_CERT_URI
#ifdef CONFIG_WOT_RD_CERT_URI
static const coap_resource_t _resources[] = {
    { CONFIG_WOT_CLIENT_CERT_URI, COAP_PUT, _cli_cert_handler, NULL },
    { CONFIG_WOT_RD_CERT_URI, COAP_GET, _rd_cert_handler, NULL },
};
#endif /*CONFIG_WOT_RD_CERT_URI*/
#endif /*CONFIG_WOT_CLIENT_CERT_URI*/

static const char *_link_params[] = {
    ";ct=0;rt=\"count\";obs",
    NULL
};

gcoap_listener_t listener = {
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
        if (pdu->payload_len) {
            unsigned content_type = coap_get_content_type(pdu);
            if (content_type == COAP_FORMAT_CBOR) {
                printf("\n---received client cert---\n");
                DEBUG("CBOR cert size:%d\n", pdu->payload_len);
                printf("c509 cert:");
                for (int i = 0; i < pdu->payload_len; i++) {
                    printf("%02X", pdu->payload[i]);
                }
                printf("\n");

                CborError err = wot_parse_cbor_cert(pdu->payload, pdu->payload_len);
                if (err) {
                    printf("CBOR parsing failure\n");
                    return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
                }
                return gcoap_response(pdu, buf, len, COAP_CODE_CHANGED);
            }
            else {
                return gcoap_response(pdu, buf, len, COAP_CODE_BAD_REQUEST);
            }
        }
    }

    return 0;
}

static ssize_t _rd_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    puts("---received cert request from client---");
    /*creating cbor client cert*/
    uint8_t c_buf[CBOR_BUFSIZE];
    memset(c_buf, 0, CBOR_BUFSIZE);
    int cbor_len = wot_get_cbor_certificate(c_buf);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_CBOR);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* write the cbor cert in the response buffer */
    if (pdu->payload_len >= cbor_len) {
        memcpy(pdu->payload, c_buf, cbor_len);
        puts("sent rd cert to client");
        DEBUG("total response len:%d\n",resp_len+cbor_len);
        return resp_len + cbor_len;
    }
    else {
        puts("msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
}


