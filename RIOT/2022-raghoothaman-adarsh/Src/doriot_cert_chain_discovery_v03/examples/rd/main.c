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
#include <string.h>
#include "msg.h"
#include "shell.h"
#include "fmt.h"
#include "doriot_wot_rd.h"


#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

extern int rd_start_cmd_app(int argc, char **argv);
extern int find_cert_cmd_app(int argc, char **argv);
extern int delete_cert_cmd_app(int argc, char **argv);
extern int add_cert_cmd_app(int argc, char **argv);
extern int print_time(int argc, char **argv);


static const shell_command_t shell_commands[] = {
    { "rd", "start resource directory", rd_start_cmd_app },
    { "find", "find cert from list", find_cert_cmd_app },
    { "del", "delete a cert from list", delete_cert_cmd_app },
    { "add", "add a cert to list", add_cert_cmd_app },
    { "time", "print time", print_time },
    { NULL, NULL, NULL }
};



static unsigned char og_priv_key_rd[] = {
    0x3A, 0x8D, 0xFF, 0xFB, 0xAE, 0x7D, 0x8F, 0xA4, 0xAF, 0x3F, 0x37, 0x8E, 0x14, 0x2C, 0x60, 0x2C,
    0x9C, 0xDD, 0x01, 0xE3, 0x2C, 0xD7, 0xCD, 0x3A, 0xE7, 0xF7, 0x36, 0x1C, 0xFD, 0xBF, 0x61, 0x89

};

static unsigned char og_pub_key_rd[] = {
    0x6E, 0x0B, 0xD3, 0xE6, 0x92, 0x58, 0xB4, 0x38, 0x82, 0xC6, 0xAE, 0x0B, 0xE1, 0x9F, 0x50, 0x4A,
    0xB2, 0x40, 0x6D, 0xE3, 0xCB, 0xC2, 0x93, 0x27, 0x4E, 0x59, 0x37, 0x36, 0xC0, 0x80, 0xC1, 0x73,
    0x06, 0xDE, 0x7C, 0x6E, 0x4E, 0xC8, 0x6B, 0xD5, 0x92, 0xDE, 0x98, 0x09, 0x1B, 0x06, 0x2A, 0x8C,
    0x68, 0x6F, 0x9E, 0xAF, 0x74, 0x47, 0x58, 0x86, 0xD8, 0x2C, 0x17, 0x68, 0xF4, 0x69, 0xB5, 0x0F
};

static unsigned char psk_key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};


static void _set_credentials(wot_credentials_t *credentials)
{
    memcpy(credentials->private_key, og_priv_key_rd, sizeof(og_priv_key_rd));
    memcpy(credentials->public_key, og_pub_key_rd, sizeof(og_pub_key_rd));
    memcpy(credentials->psk_key, psk_key, sizeof(psk_key));
}

int main(void)
{
    puts("wot cert exchange rd\n");
    /*provide key pair to the module*/
    wot_credentials_t credentials;
    _set_credentials(&credentials);
    wot_provision_keys(&credentials);
    wot_rd_start();

    /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should never be reached */
    return 0;
}
