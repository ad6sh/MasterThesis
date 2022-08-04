/**
 * @file client.c
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
#include "wot_client.h"

#define ENABLE_DEBUG 1
#include "debug.h"

static bool _proxied = false;
/* Retain request path to re-request if response includes block. User must not
 * start a new request (with a new path) until any blockwise transfer
 * completes or times out. */
#define _LAST_REQ_PATH_MAX (64)
static char _last_req_path[_LAST_REQ_PATH_MAX];

/*
 * Response callback.
 */
static void _resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
                          const sock_udp_ep_t *remote)
{
    (void)remote;       /* not interested in the source currently */

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        printf("gcoap: timeout for msg ID %02u\n", coap_get_id(pdu));
        return;
    }
    else if (memo->state == GCOAP_MEMO_RESP_TRUNC) {
        /* The right thing to do here would be to look into whether at least
         * the options are complete, then to mentally trim the payload to the
         * next block boundary and pretend it was sent as a Block2 of that
         * size. */
        printf("gcoap: warning, incomplete response; continuing with the truncated payload\n");
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
        printf("gcoap: error in response\n");
        return;
    }

    coap_block1_t block;
    if (coap_get_block2(pdu, &block) && block.blknum == 0) {
        puts("--- blockwise start ---");
    }

    char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                      ? "Success" : "Error";
    printf("gcoap: response %s, code %1u.%02u", class_str,
           coap_get_code_class(pdu),
           coap_get_code_detail(pdu));
    if (pdu->payload_len) {
        unsigned content_type = coap_get_content_type(pdu);
        if (content_type == COAP_FORMAT_TEXT
            || content_type == COAP_FORMAT_LINK
            || coap_get_code_class(pdu) == COAP_CLASS_CLIENT_FAILURE
            || coap_get_code_class(pdu) == COAP_CLASS_SERVER_FAILURE) {
            /* Expecting diagnostic payload in failure cases */
            printf(", %u bytes\n%.*s\n", pdu->payload_len, pdu->payload_len,
                   (char *)pdu->payload);
        }
        else if (content_type == COAP_FORMAT_CBOR) {
            printf("\n----received rd cert ----\n");
            DEBUG("CBOR cert size:%d\n", pdu->payload_len);
            printf("c509 cert:");
            for (int i = 0; i < pdu->payload_len; i++) {
                printf("%02X", pdu->payload[i]);
            }
            printf("\n");

            CborError err = wot_parse_cbor_cert(pdu->payload, pdu->payload_len);
            if (err) {
                printf("CBOR parsing failure\n");
                return;
            }
            else {
                /*sending client certificate to rd*/
                coap_put_cli_cert(remote);
            }
        }
        else {
            printf(", %u bytes\n", pdu->payload_len);
            od_hex_dump(pdu->payload, pdu->payload_len, OD_WIDTH_DEFAULT);
        }
    }
    else {
        printf(", empty payload\n");
    }
    /* ask for next block if present */
    if (coap_get_block2(pdu, &block)) {
        if (block.more) {
            unsigned msg_type = coap_get_type(pdu);
            if (block.blknum == 0 && !strlen(_last_req_path)) {
                puts("Path too long; can't complete blockwise");
                return;
            }

            if (_proxied) {
                gcoap_req_init(pdu, (uint8_t *)pdu->hdr, CONFIG_GCOAP_PDU_BUF_SIZE,
                               COAP_METHOD_GET, NULL);
            }
            else {
                gcoap_req_init(pdu, (uint8_t *)pdu->hdr, CONFIG_GCOAP_PDU_BUF_SIZE,
                               COAP_METHOD_GET, _last_req_path);
            }

            if (msg_type == COAP_TYPE_ACK) {
                coap_hdr_set_type(pdu->hdr, COAP_TYPE_CON);
            }
            block.blknum++;
            coap_opt_add_block2_control(pdu, &block);

            if (_proxied) {
                coap_opt_add_proxy_uri(pdu, _last_req_path);
            }

            int len = coap_opt_finish(pdu, COAP_OPT_FINISH_NONE);
            gcoap_req_send((uint8_t *)pdu->hdr, len, remote,
                           _resp_handler, memo->context);
        }
        else {
            puts("--- blockwise complete ---");
        }
    }
}


static bool _set_remote(sock_udp_ep_t *remote, char *addr_str)
{
    netif_t *netif;
    if (netutils_get_ipv6((ipv6_addr_t *)&remote->addr, &netif, addr_str) < 0) {
        puts("unable to parse destination address");
        return false;
    }
    remote->netif = netif ? netif_get_id(netif) : SOCK_ADDR_ANY_NETIF;
    remote->family = AF_INET6;

    /* set port */
    remote->port = (uint16_t)CONFIG_GCOAP_PORT;
    if (remote->port == 0) {
        puts("unable to parse destination port");
        return false;
    }
    return true;
}


#ifdef CONFIG_WOT_RD_CERT_URI
int coap_get_rd_cert(char *addr_str)
{
    /*coap get */
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;
    unsigned msg_type = COAP_TYPE_NON;
    int uri_len = strlen(CONFIG_WOT_RD_CERT_URI);

    gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET,
                   CONFIG_WOT_RD_CERT_URI);
    coap_hdr_set_type(pdu.hdr, msg_type);
    memset(_last_req_path, 0, _LAST_REQ_PATH_MAX);
    if (uri_len < _LAST_REQ_PATH_MAX) {
        memcpy(_last_req_path, CONFIG_WOT_RD_CERT_URI, uri_len);
    }
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);

    sock_udp_ep_t remote;
    if (!_set_remote(&remote, addr_str)) {
        return 1;
    }
    size_t bytes_sent = gcoap_req_send(&buf[0], len, &remote, _resp_handler, NULL);
    if (bytes_sent > 0) {
        puts("requested rd cert");
    }
    else {
        puts("failed to request rd cert");
        return 1;
    }
    return 0;
}
#endif /*CONFIG_WOT_RD_CERT_URI*/


#ifdef CONFIG_WOT_CLIENT_CERT_URI
int coap_put_cli_cert(const sock_udp_ep_t *remote)
{

    /*creating cbor client cert*/
    printf("\n\n---sending client cert---\n");
    uint8_t c_buf[CBOR_BUFSIZE];
    memset(c_buf, 0, CBOR_BUFSIZE);
    int cbor_len = wot_get_cbor_certificate(c_buf);

    /*coap put */
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;
    unsigned msg_type = COAP_TYPE_NON;
    int uri_len = strlen(CONFIG_WOT_CLIENT_CERT_URI);

    gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_PUT,
                   CONFIG_WOT_CLIENT_CERT_URI);
    coap_hdr_set_type(pdu.hdr, msg_type);

    memset(_last_req_path, 0, _LAST_REQ_PATH_MAX);
    if (uri_len < _LAST_REQ_PATH_MAX) {
        memcpy(_last_req_path, CONFIG_WOT_CLIENT_CERT_URI, uri_len);
    }
    coap_opt_add_format(&pdu, COAP_FORMAT_CBOR);
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
    memcpy(pdu.payload, c_buf, cbor_len);
    len += cbor_len;
    DEBUG("total len:%d\n",len);
    size_t bytes_sent = gcoap_req_send(&buf[0], len, remote, _resp_handler, NULL);
    if (bytes_sent > 0) {
        puts("sent client cert to rd");
    }
    else {
        puts("failed to sent client cert to rd");
        return 1;
    }
    return 0;
}
#endif /*CONFIG_WOT_CLIENT_CERT_URI*/
