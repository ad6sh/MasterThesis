/**
 * @file main.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-01-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <stdio.h>
#include "msg.h"
#include "shell.h"

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];
extern int cbor_encoder(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "cbor_encode", "convert x509 cert.pem to c509", cbor_encoder },
    { NULL, NULL, NULL }
};

int main(void)
{
    printf("x509 CBOR encoder\n");
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
