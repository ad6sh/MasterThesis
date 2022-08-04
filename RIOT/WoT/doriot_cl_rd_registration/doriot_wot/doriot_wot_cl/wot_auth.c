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



static int _add_credentials_psk(void)
{
    //TODO
    DEBUG("added psk credentials!\n");
    return 0;
}

static int _add_credentials_root(void)
{
    DEBUG("root cert verification not yet implemented!\n");
    DEBUG("please select \"psk\"\n");
    return 1;
}

static int _add_credentials_oob(void)
{
    DEBUG("oob vertification not yet implemented!\n");
    DEBUG("please select \"psk\"\n");
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
