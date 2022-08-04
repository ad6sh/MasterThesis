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
#include "keys.h"
#include "wot_cbor.h"



#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];


extern int wot_get_test_cert(int argc, char **argv);


extern int wot_create_k(int argc, char **argv);
extern int wot_print_k(int argc, char **argv);
extern int wot_print_cp(int argc, char **argv);




static const shell_command_t shell_commands[] = {
    { "wotg", "get test cbor cert", wot_get_test_cert },
    //{ "wotk", "create keys", wot_create_k },
    { "wotp", "print keys", wot_print_k },
    { "wotcp", "public key compression test", wot_print_cp },



    { NULL, NULL, NULL }
};

int main(void)
{
    //wot_create_keys();

    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should never be reached */
    return 0;
}
