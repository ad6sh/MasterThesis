/**
 * @file wot_client.c
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
#include "wot_client.h"

#define ENABLE_DEBUG 1
#include "debug.h"

static bool _proxied = false;
/* Retain request path to re-request if response includes block. User must not
 * start a new request (with a new path) until any blockwise transfer
 * completes or times out. */
#define _LAST_REQ_PATH_MAX (64)
static char _last_req_path[_LAST_REQ_PATH_MAX];
static sock_udp_ep_t remote_rd;

int (*resource_discovery_callback)(int, sock_udp_ep_t);
int (*registration_callback)(int);
int (*lookup_callback)(int, wot_cert_t *);

/*
 * Response callback for registration when rd certificate is requested.
 */
static void _reg_resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
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
        puts("gcoap: warning, incomplete response; continuing with the truncated payload\n");
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
        puts("gcoap: error in response\n");
        return;
    }

    char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                      ? "Success" : "Error";
    DEBUG("gcoap: response %s, code %1u.%02u", class_str,
           coap_get_code_class(pdu),
           coap_get_code_detail(pdu));
    if (pdu->payload_len) {
        unsigned content_type = coap_get_content_type(pdu);

        if (content_type == COAP_FORMAT_LINK) {
            /* Expecting resoucrce discovery reply */
            DEBUG(", %u bytes\n%.*s\n", pdu->payload_len, pdu->payload_len,
                   (char *)pdu->payload);

            memcpy(&remote_rd, remote, sizeof(remote_rd));
            registration_callback(REGISTRATION_FAILURE);
        }

        else if (content_type == COAP_FORMAT_TEXT
                 || coap_get_code_class(pdu) == COAP_CLASS_CLIENT_FAILURE
                 || coap_get_code_class(pdu) == COAP_CLASS_SERVER_FAILURE) {
            /* Expecting diagnostic payload in failure cases */
            printf(", %u bytes\n%.*s\n", pdu->payload_len, pdu->payload_len,
                   (char *)pdu->payload);
            registration_callback(REGISTRATION_FAILURE);
        }
        else if (content_type == COAP_FORMAT_CBOR) {
            DEBUG("\n----received rd cert ----\n");
            DEBUG("CBOR cert size:%d\n", pdu->payload_len);
            print_hex("\nc509 cert : ", pdu->payload, (unsigned int)pdu->payload_len);

            CborError err =wot_parse_cbor_cert_rd(pdu->payload, pdu->payload_len);
            if (err) {
                DEBUG("CBOR parsing failure\n");
                registration_callback(REGISTRATION_FAILURE);
                return;
            }
            else {
                /*sending client certificate to rd*/
                wot_coap_put_cli_cert(&remote_rd);
                return;
            }
        }
        else {
            DEBUG(", %u bytes\n", pdu->payload_len);
            od_hex_dump(pdu->payload, pdu->payload_len, OD_WIDTH_DEFAULT);
            registration_callback(REGISTRATION_FAILURE);
        }
    }
    else {
        DEBUG(", empty payload\n");
        registration_callback(REGISTRATION_FAILURE);
    }
}



/*
 * Response callback for registration when after succefully puting client cert in rd.
 */
static void _reg_resp_handler_final(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
                                    const sock_udp_ep_t *remote)
{
    (void)remote;       /* not interested in the source currently */

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        DEBUG("gcoap: timeout for msg ID %02u\n", coap_get_id(pdu));
        registration_callback(REGISTRATION_FAILURE);
        return;
    }
    else if (memo->state == GCOAP_MEMO_RESP_TRUNC) {
        /* The right thing to do here would be to look into whether at least
         * the options are complete, then to mentally trim the payload to the
         * next block boundary and pretend it was sent as a Block2 of that
         * size. */
        DEBUG("gcoap: warning, incomplete response; continuing with the truncated payload\n");
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
        DEBUG("gcoap: error in response\n");
        registration_callback(REGISTRATION_FAILURE);
        return;
    }

    char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                      ? "Success" : "Error";
    DEBUG("gcoap: response %s, code %1u.%02u\n", class_str,
           coap_get_code_class(pdu),
           coap_get_code_detail(pdu));
    if (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS) {
        registration_callback(REGISTRATION_SUCCESS);
    }
    else {
        registration_callback(REGISTRATION_FAILURE);
    }
}


/*
 * Response callback for resource discovery.
 */
static void _disc_resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
                               const sock_udp_ep_t *remote)
{
    (void)remote;       /* not interested in the source currently */

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        DEBUG("gcoap: timeout for msg ID %02u\n", coap_get_id(pdu));
        resource_discovery_callback(DISCOVERY_FAILURE, remote_rd);
        return;
    }
    else if (memo->state == GCOAP_MEMO_RESP_TRUNC) {
        /* The right thing to do here would be to look into whether at least
         * the options are complete, then to mentally trim the payload to the
         * next block boundary and pretend it was sent as a Block2 of that
         * size. */
        DEBUG("gcoap: warning, incomplete response; continuing with the truncated payload\n");
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
        DEBUG("gcoap: error in response\n");
        resource_discovery_callback(DISCOVERY_FAILURE, remote_rd);
        return;
    }

    char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                      ? "Success" : "Error";
    DEBUG("gcoap: response %s, code %1u.%02u", class_str,
           coap_get_code_class(pdu),
           coap_get_code_detail(pdu));
    if (pdu->payload_len) {
        unsigned content_type = coap_get_content_type(pdu);

        if (content_type == COAP_FORMAT_LINK) {
            /* Expecting resoucrce discovery reply */
            DEBUG(", %u bytes\n%.*s\n", pdu->payload_len, pdu->payload_len,
                   (char *)pdu->payload);

            memcpy(&remote_rd, remote, sizeof(remote_rd));
            resource_discovery_callback(DISCOVERY_SUCCESS, remote_rd);
        }

        else if (content_type == COAP_FORMAT_TEXT
                 || coap_get_code_class(pdu) == COAP_CLASS_CLIENT_FAILURE
                 || coap_get_code_class(pdu) == COAP_CLASS_SERVER_FAILURE) {
            /* Expecting diagnostic payload in failure cases */
            DEBUG(", %u bytes\n%.*s\n", pdu->payload_len, pdu->payload_len,
                   (char *)pdu->payload);
            resource_discovery_callback(DISCOVERY_FAILURE, remote_rd);
        }
        else {
            DEBUG(", %u bytes\n", pdu->payload_len);
            od_hex_dump(pdu->payload, pdu->payload_len, OD_WIDTH_DEFAULT);
            resource_discovery_callback(DISCOVERY_FAILURE, remote_rd);
        }
    }
    else {
        DEBUG(", empty payload\n");
        resource_discovery_callback(DISCOVERY_FAILURE, remote_rd);
    }

}


uint32_t got_resp_lkup;
/*
 * Response callback for lookup.
 */
static void _lookup_resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
                                 const sock_udp_ep_t *remote)
{
    (void)remote;       /* not interested in the source currently */
    
    got_resp_lkup = xtimer_now_usec();

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        DEBUG("gcoap: timeout for msg ID %02u\n", coap_get_id(pdu));
        lookup_callback(LOOKUP_FAILURE, NULL);
        return;
    }
    else if (memo->state == GCOAP_MEMO_RESP_TRUNC) {
        /* The right thing to do here would be to look into whether at least
         * the options are complete, then to mentally trim the payload to the
         * next block boundary and pretend it was sent as a Block2 of that
         * size. */
        puts("gcoap: warning, incomplete response; continuing with the truncated payload\n");
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
        DEBUG("gcoap: error in response\n");
        lookup_callback(LOOKUP_FAILURE, NULL);
        return;
    }

    char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                      ? "Success" : "Error";
    DEBUG("gcoap: response %s, code %1u.%02u", class_str,
           coap_get_code_class(pdu),
           coap_get_code_detail(pdu));
    if (pdu->payload_len) {
        unsigned content_type = coap_get_content_type(pdu);
        if (content_type == COAP_FORMAT_TEXT
            || content_type == COAP_FORMAT_LINK
            || coap_get_code_class(pdu) == COAP_CLASS_CLIENT_FAILURE
            || coap_get_code_class(pdu) == COAP_CLASS_SERVER_FAILURE) {
            /* Expecting diagnostic payload in failure cases */
            DEBUG(", %u bytes\n%.*s\n", pdu->payload_len, pdu->payload_len,
                   (char *)pdu->payload);
            lookup_callback(LOOKUP_FAILURE, NULL);
        }
        else if (content_type == COAP_FORMAT_CBOR) {
            DEBUG("\n----received lookup response ----\n");
            DEBUG("CBOR cert size:%d\n", pdu->payload_len);
            print_hex("CBOR response  : ", pdu->payload, (unsigned int)pdu->payload_len);

            CborError err = wot_parse_cbor_cert_lookup(pdu->payload, pdu->payload_len);
            if (err) {
                puts("CBOR parsing failure lookup response\n");
                lookup_callback(LOOKUP_FAILURE, NULL);
                return;
            }
            else {
                //lookup_callback(LOOKUP_SUCCESS);
            }
        }
        else {
            DEBUG(", %u bytes\n", pdu->payload_len);
            od_hex_dump(pdu->payload, pdu->payload_len, OD_WIDTH_DEFAULT);
            lookup_callback(LOOKUP_FAILURE, NULL);
        }
    }
    else {
        DEBUG(", empty payload\n");
        lookup_callback(LOOKUP_FAILURE, NULL);
    }
}




#ifdef CONFIG_WOT_RD_CERT_URI
int wot_register_client(int (*callback)(int))
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

    registration_callback = callback;


    size_t bytes_sent = gcoap_req_send(&buf[0], len, &remote_rd, _reg_resp_handler, NULL);

    if (bytes_sent > 0) {
        DEBUG("requested rd cert");
    }
    else {
        DEBUG("failed to request rd cert");
        registration_callback(REGISTRATION_FAILURE);
        return 1;
    }
    return 0;
}
#endif /*CONFIG_WOT_RD_CERT_URI*/


#ifdef CONFIG_WOT_CLIENT_CERT_URI
int wot_coap_put_cli_cert(const sock_udp_ep_t *remote)
{
    /*creating cbor client cert*/
    DEBUG("\n\n---sending client cert---\n");
    //uint8_t c_buf[CBOR_BUFSIZE];
    //uint8_t client_c_buf[100] = {0};
    //memset(c_buf, 0, CBOR_BUFSIZE);

    uint8_t *client_c_buf = (uint8_t *)calloc(CBOR_BUFSIZE, sizeof(uint8_t));
    int cbor_len = wot_get_cbor_certificate_client(client_c_buf);

    /*coap put */
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len = 0;
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
    memcpy(pdu.payload, client_c_buf, cbor_len);
    len += cbor_len;
    DEBUG("total coap len:%d\n", len);
    size_t bytes_sent = gcoap_req_send(&buf[0], len, remote, _reg_resp_handler_final, NULL);
    if (bytes_sent > 0) {
        DEBUG("sent client cert to rd");
    }
    else {
        DEBUG("failed to sent client cert to rd");
        return 1;
    }
    free(client_c_buf);
    return 0;
}
#endif /*CONFIG_WOT_CLIENT_CERT_URI*/

//uint32_t prepare_rq_start;
uint32_t prepare_rq_end;
#ifdef CONFIG_WOT_LOOKUP_CERT_URI
int wot_lookup_client(char *lookup_name, int (*callback)(int, wot_cert_t *))
{
    /*coap get */
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    uint8_t c_buf[32];
    uint8_t cbor_len;
    coap_pkt_t pdu;
    size_t len;

    unsigned msg_type = COAP_TYPE_NON;
    int uri_len = strlen(CONFIG_WOT_LOOKUP_CERT_URI);

    gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET,
                   CONFIG_WOT_LOOKUP_CERT_URI);
    coap_hdr_set_type(pdu.hdr, msg_type);
    memset(_last_req_path, 0, _LAST_REQ_PATH_MAX);
    if (uri_len < _LAST_REQ_PATH_MAX) {
        memcpy(_last_req_path, CONFIG_WOT_LOOKUP_CERT_URI, uri_len);
    }
    coap_opt_add_format(&pdu, COAP_FORMAT_CBOR);
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_PAYLOAD);
    cbor_len = wot_get_lookup_payload(c_buf, lookup_name);
    DEBUG("buf len:%d\n", cbor_len);
    memcpy(pdu.payload, c_buf, cbor_len);
    len += cbor_len;

    lookup_callback = callback;
    
    prepare_rq_end = xtimer_now_usec();
    
    size_t bytes_sent = gcoap_req_send(&buf[0], len, &remote_rd, _lookup_resp_handler, NULL);
    if (bytes_sent > 0) {
        DEBUG("requested lookup cert");
    }
    else {
        DEBUG("failed to request lookup cert");
        lookup_callback(LOOKUP_FAILURE, NULL);
        return 1;
    }

    return 0;
}
#endif /*CONFIG_WOT_LOOKUP_CERT_URI*/

/*--------------resource discovery-----------------------*/
static bool _set_remote_multicast(sock_udp_ep_t *remote, char *addr_str)
{
    ipv6_addr_t addr;

    remote->family = AF_INET6;

    /* parse for interface */
    char *iface = ipv6_addr_split_iface(addr_str);
    if (!iface) {
        if (gnrc_netif_numof() == 1) {
            /* assign the single interface found in gnrc_netif_numof() */
            remote->netif = (uint16_t)gnrc_netif_iter(NULL)->pid;
        }
        else {
            remote->netif = SOCK_ADDR_ANY_NETIF;
        }
    }
    else {
        if (gnrc_netif_get_by_pid(atoi(iface)) == NULL) {
            DEBUG("[CoAP] interface not valid");
            return false;
        }
        remote->netif = atoi(iface);
    }

    /* parse destination address */
    if (ipv6_addr_from_str(&addr, addr_str) == NULL) {
        DEBUG("[CoAP] unable to parse destination address");
        return false;
    }
    if ((remote->netif == SOCK_ADDR_ANY_NETIF) && ipv6_addr_is_link_local(&addr)) {
        DEBUG("[CoAP] must specify interface for link local target");
        return false;
    }
    memcpy(&remote->addr.ipv6[0], &addr.u8[0], sizeof(addr.u8));

    /* parse port */
    remote->port = CONFIG_GCOAP_PORT;

    return true;

}


int wot_discover_rd(int (*callback)(int, sock_udp_ep_t))
{
    //coap get
    uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
    coap_pkt_t pdu;
    size_t len;
    unsigned msg_type = COAP_TYPE_NON; //COAP_TYPE_NON
    int uri_len = strlen(WELL_KNOWN_URI);

    gcoap_req_init(&pdu, &buf[0], CONFIG_GCOAP_PDU_BUF_SIZE, COAP_METHOD_GET,
                   WELL_KNOWN_URI);

    coap_hdr_set_type(pdu.hdr, msg_type);
    memset(_last_req_path, 0, _LAST_REQ_PATH_MAX);
    if (uri_len < _LAST_REQ_PATH_MAX) {
        memcpy(_last_req_path, WELL_KNOWN_URI, uri_len);
    }
    coap_opt_add_uri_query(&pdu, "rt", "wotdisc");
    len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);

    sock_udp_ep_t remote;
    if (!_set_remote_multicast(&remote, MULTI_CAST_ADDR)) {
        DEBUG("failed to set remote address");
        return 1;
    }

    resource_discovery_callback = callback;

    size_t bytes_sent = gcoap_req_send(&buf[0], len, &remote, _disc_resp_handler, NULL);
    if (bytes_sent > 0) {
        DEBUG("requested resource discovery");
    }
    else {
        DEBUG("failed to request resource discovery");
        return 1;
    }
    return 0;
}
