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

#include "net/gcoap.h"
#include "shell.h"

extern int wot_client_cmd(int argc, char **argv);
extern int wot_rd_cmd(int argc, char **argv);
extern int wot_find_cert(int argc, char **argv);


#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

static const shell_command_t shell_commands[] = {
    { "wotc", "Start a WoT client", wot_client_cmd },
    { "wotrd", "Start a WoT rd", wot_rd_cmd },
    { "wotf", "find a cert", wot_find_cert },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    puts("Wot cert exchange\n");
    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    /* should never be reached */
    return 0;
}
