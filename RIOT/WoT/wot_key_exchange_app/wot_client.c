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

#define ENABLE_DEBUG 0
#include "debug.h"

static int _coap_put_cli_cert(const sock_udp_ep_t *remote);
static int _coap_get_rd_cert(char *addr_str);

#define CLIENT_CERT_URI "/cli/cert"
#define RD_CERT_URI "/rd/cert"

static bool _proxied = false;
static sock_udp_ep_t _proxy_remote;
//static char proxy_uri[64];

/* Retain request path to re-request if response includes block. User must not
 * start a new request (with a new path) until any blockwise transfer
 * completes or times out. */
#define _LAST_REQ_PATH_MAX (64)
static char _last_req_path[_LAST_REQ_PATH_MAX];

uint16_t req_count = 0;

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
                _coap_put_cli_cert(remote);
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

static bool _parse_endpoint(sock_udp_ep_t *remote,
                            const char *addr_str, const char *port_str)
{
    netif_t *netif;

    /* parse hostname */
    if (netutils_get_ipv6((ipv6_addr_t *)&remote->addr, &netif, addr_str) < 0) {
        puts("unable to parse destination address");
        return false;
    }
    remote->netif = netif ? netif_get_id(netif) : SOCK_ADDR_ANY_NETIF;
    remote->family = AF_INET6;

    /* parse port */
    remote->port = atoi(port_str);
    if (remote->port == 0) {
        puts("unable to parse destination port");
        return false;
    }

    return true;
}

static size_t _send(uint8_t *buf, size_t len, char *addr_str, char *port_str)
{
    size_t bytes_sent;
    sock_udp_ep_t *remote;
    sock_udp_ep_t new_remote;

    if (_proxied) {
        remote = &_proxy_remote;
    }
    else {
        if (!_parse_endpoint(&new_remote, addr_str, port_str)) {
            return 0;
        }
        remote = &new_remote;
    }

    bytes_sent = gcoap_req_send(buf, len, remote, _resp_handler, NULL);
    if (bytes_sent > 0) {
        req_count++;
    }
    return bytes_sent;
}

static int _print_usage_cli(char **argv)
{
    printf("usage: %s [-v <verify_type>] <rd_addr>\n", argv[0]);
    printf(
        "      verify_type: key verification type.Either psk,root,oob can be selected (default:psk)\n");
    return 1;
}

int wot_client_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    /*for key exchange phase,key verification can be done using Pre-shared key,root certiciate,nfc,button press in wifi routers.
       Admin can choose which method to use.These methods can be extented.*/
    char *verify_types[] = { "psk", "root", "oob" };
    //char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];

    if (argc == 1) {
        return _print_usage_cli(argv);
    }

    if (strcmp(argv[1], "-help") == 0) {
        /* show help for commands */
        return _print_usage_cli(argv);
    }
    else if (strcmp(argv[1], "-v") == 0) {
        if (argc != 4) {
            return _print_usage_cli(argv);
        }
        /*if -v option is specified,verification type shoud be found*/
        int verify_pos = -1;
        for (size_t i = 0; i < ARRAY_SIZE(verify_types); i++) {
            if (strcmp(argv[2], verify_types[i]) == 0) {
                verify_pos = i;
            }
        }
        if (verify_pos == -1) {
            return _print_usage_cli(argv);
        }
        if (wot_add_verify_method(verify_pos) != 0) {
            printf("failed to add verification method:%s\n", verify_types[verify_pos]);
            return 1;
        }
        else {
            DEBUG("rd ip address :%s\n", argv[3]);
            _coap_get_rd_cert(argv[3]);
        }
    }
    
    else if (argc == 2) {
        /*add default verification method PSK,if successfull request rd certificate*/
        DEBUG("adding default verification method:%s\n", verify_types[DEFAULT_VERIFY_TYPE]);
        if (wot_add_verify_method(DEFAULT_VERIFY_TYPE) != 0) {
            printf("failed to add verification method:%s\n", verify_types[DEFAULT_VERIFY_TYPE]);
            return 1;
        }
        else {
            DEBUG("rd ip address :%s\n", argv[1]);
            _coap_get_rd_cert(argv[1]);
        }
    }
    return 0;

}


static int _coap_get_rd_cert(char *addr_str)
{
    /*coap get */
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;
    unsigned msg_type = COAP_TYPE_NON;
    int uri_len = strlen(RD_CERT_URI);

    gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET, RD_CERT_URI);
    coap_hdr_set_type(pdu.hdr, msg_type);
    memset(_last_req_path, 0, _LAST_REQ_PATH_MAX);
    if (uri_len < _LAST_REQ_PATH_MAX) {
        memcpy(_last_req_path, RD_CERT_URI, uri_len);
    }
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);

    if (!_send(&buf[0], len, addr_str, GCOAP_DTLS_PORT_STR)) {
        printf("rd cert request failed\n");
        return 1;
    }
    else {
        printf("requested rd cert\n");
    }
    return 0;

}


static int _coap_put_cli_cert(const sock_udp_ep_t *remote)
{
    (void)remote;
    /*creating cbor client cert*/
    printf("\n\n---sending client cert---\n");
    uint8_t c_buf[CBOR_BUFSIZE];
    int cbor_len = wot_get_cbor_certificate(c_buf, CBOR_CLI_CERT);

    /*coap put */
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;
    unsigned msg_type = COAP_TYPE_NON;
    int uri_len = strlen(CLIENT_CERT_URI);

    gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_PUT, CLIENT_CERT_URI);
    coap_hdr_set_type(pdu.hdr, msg_type);

    memset(_last_req_path, 0, _LAST_REQ_PATH_MAX);
    if (uri_len < _LAST_REQ_PATH_MAX) {
        memcpy(_last_req_path, CLIENT_CERT_URI, uri_len);
    }
    coap_opt_add_format(&pdu, COAP_FORMAT_CBOR);
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
    memcpy(pdu.payload, c_buf, cbor_len);
    len += cbor_len;

    char ipv6_addr[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(ipv6_addr, (ipv6_addr_t *)remote->addr.ipv6, IPV6_ADDR_MAX_STR_LEN);
    DEBUG("remote rd  address: %s\n", ipv6_addr);

    if (!_send(&buf[0], len, ipv6_addr, GCOAP_DTLS_PORT_STR)) {
        printf("failed to send client cert to rd\n");
        return 1;
    }
    else {
        printf("sent client cert to rd\n");
    }
    return 0;
}
