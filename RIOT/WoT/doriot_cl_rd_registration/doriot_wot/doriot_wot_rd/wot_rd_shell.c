/**
 * @file wot_rd_shell.c
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

#include "shell.h"
#include "net/gcoap.h"

#include "xfa.h"

#include "wot_cbor.h"
#include "wot_auth.h"

#define ENABLE_DEBUG 0
#include "debug.h"



static int _print_usage_rd(char **argv)
{
    printf("usage: %s start\n", argv[0]);
    return 1;
}


extern gcoap_listener_t listener;

int wot_rd_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    char *verify_types[] = { "psk", "root", "oob" };

    if (argc == 1) {
        return _print_usage_rd(argv);
    }

    if (strcmp(argv[1], "-help") == 0) {
        return _print_usage_rd(argv);
    }

    else if ((strcmp(argv[1], "start") == 0)) {
        if (argc != 2) {
            return _print_usage_rd(argv);
        }

        if (wot_add_verify_method(CONFIG_WOT_AUTH_TYPE) != 0) {
            printf("failed to add verification method:%s\n", verify_types[CONFIG_WOT_AUTH_TYPE]);
            return 1;
        }
    }
    else {
        return _print_usage_rd(argv);
    }

    gcoap_register_listener(&listener);
    printf("rd listening on port: %d\n",CONFIG_GCOAP_PORT);

    return 0;
}

XFA_USE_CONST(shell_command_t *, shell_commands_xfa);
shell_command_t rd_cmd = { "wotrd", "Start a WoT rd", wot_rd_cmd };
XFA_ADD_PTR(shell_commands_xfa, 0, sc_wot_rd_cmd, &rd_cmd);
