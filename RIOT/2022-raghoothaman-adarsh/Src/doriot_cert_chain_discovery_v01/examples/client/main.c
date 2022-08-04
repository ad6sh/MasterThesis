/**
 * @file main.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-02-16
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <stdio.h>
#include "msg.h"
#include "shell.h"
#include "doriot_wot_cl.h"

extern int wot_find_cert(int argc, char **argv);

static uint8_t cli_ecdsa_pub_key[] = {
    0xb7, 0x4e, 0xa0, 0x62, 0x96, 0xc5, 0xb9, 0x09,
    0xad, 0x36, 0x10, 0xab, 0xb1, 0xd8, 0x54, 0x69,
    0xef, 0x2b, 0x15, 0x5a, 0xb5, 0x28, 0x21, 0x21,
    0x9f, 0xa3, 0x9e, 0x6a, 0x02, 0xce, 0xb8, 0xb9,
    0xcc, 0x0e, 0x88, 0x88, 0x91, 0x80, 0x7a, 0xdd,
    0xf7, 0x4e, 0x2e, 0xe6, 0x6e, 0xd4, 0x22, 0xde,
    0xbc, 0x68, 0xcd, 0x8f, 0xd9, 0x5a, 0xa0, 0xcd,
    0x5f, 0x4a, 0x1a, 0xb7, 0x2f, 0x95, 0xfc, 0x76
};


#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

static const shell_command_t shell_commands[] = {
    { "wotf", "find a cert", wot_find_cert },
    { NULL, NULL, NULL }
};

int main(void)
{
    /*provide public key to the module*/
    wot_provision_pub_key(cli_ecdsa_pub_key);
    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("wot cert exchange client\n");
    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should never be reached */
    return 0;
}
