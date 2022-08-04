/**
 * @file wot_auth.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-02-16
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "wot_auth.h"

#define ENABLE_DEBUG 0
#include "debug.h"

static const uint8_t psk_id_0[] = PSK_DEFAULT_IDENTITY;
static const uint8_t psk_key_0[] = PSK_DEFAULT_KEY;
static const credman_credential_t credential_psk = {
    .type = CREDMAN_TYPE_PSK,
    .tag = GCOAP_DTLS_CREDENTIAL_TAG,
    .params = {
        .psk = {
            .key = { .s = psk_key_0, .len = sizeof(psk_key_0) - 1, },
            .id = { .s = psk_id_0, .len = sizeof(psk_id_0) - 1, },
        }
    },
};


static int _add_credentials_psk(void)
{
    #if IS_USED(MODULE_GCOAP_DTLS)
    int res = credman_add(&credential_psk);
    if (res < 0 && res != CREDMAN_EXIST) {
        /* ignore duplicate credentials */
        printf("gcoap: cannot add credential to system: %d\n", res);
        return 1;
    }
    sock_dtls_t *gcoap_sock_dtls = gcoap_get_sock_dtls();
    res = sock_dtls_add_credential(gcoap_sock_dtls, GCOAP_DTLS_CREDENTIAL_TAG);
    if (res < 0) {
        printf("gcoap: cannot add credential to DTLS sock: %d\n", res);
    }
    printf("added  psk verification method\n");
    #endif
    return 0;
}

static int _add_credentials_root(void)
{
    printf("root cert verification not yet implemented!\n");
    printf("please select \"psk\"\n");
    return 1;
}

static int _add_credentials_oob(void)
{
    printf("oob vertification not yet implemented!\n");
    printf("please select \"psk\"\n");
    return 1;
}


int wot_add_verify_method(int verify_pos)
{
    switch (verify_pos) {
    case 0:
        /*for PSK*/
        DEBUG("adding psk verification method\n");
        return _add_credentials_psk();
        break;
    case 1:
        /*for root*/
        DEBUG("adding root certificate verification method\n");
        return _add_credentials_root();
        break;
    case 2:
        /*for oob*/
        DEBUG("adding oob verification method\n");
        return _add_credentials_oob();
        break;
    default:
        return 1;
        break;
    }
    return 1;
}
