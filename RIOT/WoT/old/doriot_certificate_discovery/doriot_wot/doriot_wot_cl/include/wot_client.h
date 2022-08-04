#ifndef WOT_CLIENT_H
#define WOT_CLIENT_H

//#include "net/gcoap.h"
#include "net/sock/udp.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief function to put client cert in rd
 *
 * @param remote
 * @return int
 */
int coap_put_cli_cert(const sock_udp_ep_t *remote);

/**
 * @brief function get rd cert
 *
 * @param addr_str
 * @return int
 */
int coap_get_rd_cert(char *addr_str);


#ifdef __cplusplus
}
#endif

#endif /* WOT_CLIENT_H */
