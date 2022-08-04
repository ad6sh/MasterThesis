#include <stdio.h>
#include "msg.h"
#include "shell.h"


#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int x509_parse(int argc, char **argv);
extern int cbor_encoder(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "parse_cert", "reads an x509 cert.pem and parse", x509_parse },
    { "cbor_encode", "convert x509 cert.pem to cbor", cbor_encoder },
    { NULL, NULL, NULL }
};




int main(void)
{

    printf("Wolfssl pem-decoder\n\n");

    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;

}
