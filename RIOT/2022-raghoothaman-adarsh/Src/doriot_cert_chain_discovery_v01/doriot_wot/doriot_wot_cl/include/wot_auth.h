/**
 * @file wot_auth.h
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief 
 * @version 0.1
 * @date 2022-02-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef WOT_AUTH_H
#define WOT_AUTH_H

#include "net/credman.h"
#include "net/dsm.h"
#include "tinydtls_keys.h"

#include "net/gcoap.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Example credential tag for credman. Tag together with the credential type needs to be unique. */
#define GCOAP_DTLS_CREDENTIAL_TAG 10
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY "secretPSK"
#define PSK_OPTIONS "i:k:"
#define PSK_ID_MAXLEN 32
#define PSK_MAXLEN 32

/**
 * @brief function to add certificate verification method
 * 
 * @param verify_pos 
 * @return int 
 */
int wot_add_verify_method(int verify_pos);



#ifdef __cplusplus
}
#endif

#endif /* WOT_AUTH_H */
