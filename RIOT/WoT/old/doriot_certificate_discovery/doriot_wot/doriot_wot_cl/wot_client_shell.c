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
#include "shell.h"

#include "xfa.h"

#include "wot_cbor.h"
#include "wot_auth.h"
#include "wot_client.h"

#define ENABLE_DEBUG 0
#include "debug.h"


static int _print_usage_cli(char **argv)
{
    printf("usage: %s -v <verify_type> <rd_addr>\n", argv[0]);
    printf("\tverify_type: key verification type.Either psk,root,oob can be selected\n");
    return 1;
}

int wot_client_cmd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    /*for key exchange phase,key verification can be done using Pre-shared key,root certiciate,nfc,button press in wifi routers.
       Admin can choose which method to use.These methods can be extented.*/
    char *verify_types[] = { "psk", "root", "oob" };

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
            coap_get_rd_cert(argv[3]);
        }
    }
    else{
        return _print_usage_cli(argv);
    }
    return 0;

}

XFA_USE_CONST(shell_command_t *, shell_commands_xfa);
shell_command_t client_cmd = { "wotc", "Start a WoT client", wot_client_cmd };
XFA_ADD_PTR(shell_commands_xfa,0,sc_wot_client_cmd,&client_cmd);



