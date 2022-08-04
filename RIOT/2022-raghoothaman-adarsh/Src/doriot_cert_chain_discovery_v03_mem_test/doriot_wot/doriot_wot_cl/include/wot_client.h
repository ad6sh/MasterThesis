#ifndef WOT_CLIENT_H
#define WOT_CLIENT_H

/**
 * @file wot_client.h
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief 
 * @version 0.1
 * @date 2022-03-26
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include "net/sock/udp.h"
#include "wot_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WELL_KNOWN_URI "/.well-known/core"
#define MULTI_CAST_ADDR "ff02::1"
#define DISCOVERY_SUCCESS 0
#define DISCOVERY_FAILURE 1
#define REGISTRATION_SUCCESS 0
#define REGISTRATION_FAILURE 1
#define LOOKUP_SUCCESS 0
#define LOOKUP_FAILURE 1 

/**
 * @brief function to put client cert in rd
 *
 * @param remote
 * @return int
 */
int wot_coap_put_cli_cert(const sock_udp_ep_t *remote);

/**
 * @brief function to register client with rd,initiates request to get rd certificate
 *
 * @param addr_str
 * @return int
 */
int wot_register_client(int (*callback)(int));

/**
 * @brief function to lookup for client cert in rd
 * 
 * @param addr_str 
 * @param lookup_name 
 * @return int 
 */
int wot_lookup_client(char *lookup_name,int (*callback)(int,wot_cert_t *));

/**
 * @brief function to find resource directory via coap resource discovery with callback
 * 
 * @param callback 
 * @return int 
 */
int wot_discover_rd(int (*callback)(int,sock_udp_ep_t));





#ifdef __cplusplus
}
#endif

#endif /* WOT_CLIENT_H */
