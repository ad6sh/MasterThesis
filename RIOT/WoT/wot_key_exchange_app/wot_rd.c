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

#define ENABLE_DEBUG 0
#include "debug.h"

static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context);
static ssize_t _rd_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
static ssize_t _cli_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);

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
    int cbor_len = wot_get_cbor_certificate(c_buf, CBOR_RD_CERT);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_CBOR);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* write the cbor cert in the response buffer */
    if (pdu->payload_len >= cbor_len) {
        memcpy(pdu->payload, c_buf, cbor_len);
        puts("sent rd cert to client");
        DEBUG("response length:%d\n",resp_len+cbor_len);
        return resp_len + cbor_len;
    }
    else {
        puts("msg buffer too small");
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
}


static int _print_usage_rd(char **argv)
{
    printf("usage: %s [-v <verify_type>]\n", argv[0]);
    printf(
        "\tverify_type: key verification type.Either psk,root,oob can be selected (default:psk)\n");
    return 1;
}


int wot_rd_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char *verify_types[] = { "psk", "root", "oob" };

    if (strcmp(argv[1], "-help") == 0) {
        return _print_usage_rd(argv);
    }
    else if (strcmp(argv[1], "-v") == 0) {
        if (argc != 3) {
            return _print_usage_rd(argv);
        }
        /*if -v option is specified,verification type shoud be found*/
        int verify_pos = -1;
        for (size_t i = 0; i < ARRAY_SIZE(verify_types); i++) {
            if (strcmp(argv[2], verify_types[i]) == 0) {
                verify_pos = i;
            }
        }
        if (verify_pos == -1) {
            return _print_usage_rd(argv);
        }
        if (wot_add_verify_method(verify_pos) != 0) {
            printf("failed to add verification method:%s\n", verify_types[verify_pos]);
            return 1;
        }
    }
    else if (argc == 1) {
        /*add default verification method PSK*/
        DEBUG("adding default verification method:%s\n", verify_types[DEFAULT_VERIFY_TYPE]);
        if (wot_add_verify_method(DEFAULT_VERIFY_TYPE) != 0) {
            printf("failed to add verification method:%s\n", verify_types[DEFAULT_VERIFY_TYPE]);
            return 1;
        }
    }
    else {
        return _print_usage_rd(argv);
    }

    gcoap_register_listener(&_listener);

    return 0;
}
