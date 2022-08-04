/**
 * @file server.c
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
    printf("usage: %s -v <verify_type> \n", argv[0]);
    printf("\tverify_type: key verification type.Either psk,root,oob can be selected\n");
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

    else if ((strcmp(argv[1], "-v") == 0)) {
        if (argc != 3) {
            return _print_usage_rd(argv);
        }
        /*if -v option is specified,verification type shoud be found*/
        int verify_pos = -1;
        for (size_t i = 0; i < ARRAY_SIZE(verify_types); i++) {
            if (strcmp(argv[2], verify_types[i]) == 0) {
                verify_pos = i;
            }
        }
        if (verify_pos == -1) {
            return _print_usage_rd(argv);
        }
        if (wot_add_verify_method(verify_pos) != 0) {
            printf("failed to add verification method:%s\n", verify_types[verify_pos]);
            return 1;
        }
    }
    else {
        return _print_usage_rd(argv);
    }

    gcoap_register_listener(&listener);

    return 0;
}

XFA_USE_CONST(shell_command_t *, shell_commands_xfa);
shell_command_t rd_cmd = { "wotrd", "Start a WoT rd", wot_rd_cmd };
XFA_ADD_PTR(shell_commands_xfa, 0, sc_wot_rd_cmd, &rd_cmd);
