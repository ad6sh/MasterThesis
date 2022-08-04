/**
 * @file wot_rd.c
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

#include "net/gcoap.h"
#include "od.h"

#include "xtimer.h"

#include "wot_cbor.h"
#include "wot_auth.h"
#include "wot_list.h"

#define ENABLE_DEBUG 1
#include "debug.h"

static ssize_t _encode_link(const coap_resource_t *resource, char *buf,
                            size_t maxlen, coap_link_encoder_ctx_t *context);
static ssize_t _rd_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
static ssize_t _cli_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);
static ssize_t _lookup_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx);


/* CoAP resources. Must be sorted by path (ASCII order). */
#ifdef CONFIG_WOT_CLIENT_CERT_URI
#ifdef CONFIG_WOT_LOOKUP_CERT_URI
#ifdef CONFIG_WOT_RD_CERT_URI
static const coap_resource_t _resources[] = {
    { CONFIG_WOT_CLIENT_CERT_URI, COAP_PUT, _cli_cert_handler, NULL },
    { CONFIG_WOT_LOOKUP_CERT_URI, COAP_GET, _lookup_cert_handler, NULL },
    { CONFIG_WOT_RD_CERT_URI, COAP_GET, _rd_cert_handler, NULL },
};
#endif  /*CONFIG_WOT_RD_CERT_URI*/
#endif  /*CONFIG_WOT_LOOKUP_CERT_URI*/
#endif  /*CONFIG_WOT_CLIENT_CERT_URI*/

static const char *_link_params[] = {
    ";ct=0;rt=wotdisc;obs",
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
                DEBUG("\n---received client cert---\n");
                DEBUG("CBOR cert size:%d\n", pdu->payload_len);
                print_hex("c509 cert : ", pdu->payload, (unsigned int)pdu->payload_len);
                CborError err = wot_parse_cbor_cert_client(pdu->payload, pdu->payload_len);
                if (err) {
                    DEBUG("CBOR parsing failure\n");
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
    DEBUG("---received cert request from client---");
    /*creating cbor client cert*/
    //uint8_t c_buf[CBOR_BUFSIZE];
    //memset(c_buf, 0, CBOR_BUFSIZE);
    uint8_t *rd_c_buf = (uint8_t *)calloc(CBOR_BUFSIZE, sizeof(uint8_t));
    int cbor_len = wot_get_cbor_certificate_rd(rd_c_buf);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_CBOR);
    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);

    /* write the cbor cert in the response buffer */
    if (pdu->payload_len >= cbor_len) {
        memcpy(pdu->payload, rd_c_buf, cbor_len);
        DEBUG("sent rd cert to client");
        free(rd_c_buf);
        DEBUG("total response len:%d\n", resp_len + cbor_len);
        return resp_len + cbor_len;
    }
    else {
        DEBUG("msg buffer too small");
        free(rd_c_buf);
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }
    free(rd_c_buf);
}

/*--------------------------lookup interface----------------------------*/
uint32_t count_lkup=0;
uint32_t c509_start_time[50];
uint32_t c509_end_time[50];
//extern uint32_t crypto_start_time[100];
//extern uint32_t crypto_end_time[100]; 

static ssize_t _lookup_cert_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    DEBUG("---received cert lookup request from client---\n");
    c509_start_time[count_lkup]=xtimer_now_usec();

    char client_name[NAME_MAX_LEN] = { 0 };
    char lookup_name[NAME_MAX_LEN] = { 0 };
    uint8_t c_buf[CBOR_BUFSIZE] = { 0 };
    if (pdu->payload_len) {
        unsigned content_type = coap_get_content_type(pdu);
        if (content_type == COAP_FORMAT_CBOR) {
            DEBUG("lookup request payload_len:%d\n", pdu->payload_len);
            //print_hex("lookup req : ", pdu->payload, (unsigned int)pdu->payload_len);
            parse_look_up_request(pdu->payload, pdu->payload_len, client_name, lookup_name);

            if (wot_node_exists(client_name)) {
                if (wot_node_exists(lookup_name)) {
                    int cbor_len = wot_get_cbor_certificate_lookup(c_buf, lookup_name);
                    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
                    coap_opt_add_format(pdu, COAP_FORMAT_CBOR);
                    size_t resp_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
                    
                    c509_end_time[count_lkup]=xtimer_now_usec();
                    count_lkup++;
                    //write the cbor cert in the response buffer
                    if (pdu->payload_len >= cbor_len) {
                        memcpy(pdu->payload, c_buf, cbor_len);
                        DEBUG("sent cert to client");
                        DEBUG("total response len:%d + %d\n", resp_len,cbor_len);
                        return resp_len + cbor_len;
                    }
                    else {
                        DEBUG("msg buffer too small");
                        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
                    }
                }
                else {
                    DEBUG("certificate not found:%s\n", lookup_name);
                }
            }
            else {
                DEBUG("request from unauthorized client:%s\n", client_name);
            }
        }
    }
    return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
}


int wot_rd_start(void)
{
    char *verify_types[] = { "psk", "root", "oob" };

    if (wot_add_verify_method(CONFIG_WOT_AUTH_TYPE) != 0) {
        printf("failed to add verification method:%s\n", verify_types[CONFIG_WOT_AUTH_TYPE]);
        return 1;
    }
    gcoap_register_listener(&listener);
    printf("rd listening on port: %d\n", CONFIG_GCOAP_PORT);

    return 0;
}
