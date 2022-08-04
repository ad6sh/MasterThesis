#include "doriot_wot_cl.h"

#define ENABLE_DEBUG 0
#include "debug.h"

int lookup_callback_app(int status, wot_cert_t *node);

static int _print_usage_cli(char **argv)
{
    printf("usage discover: %s -d \n", argv[0]);
    printf("usage register: %s -r \n", argv[0]);
    printf("usage lookup: %s -l  <client_name>\n", argv[0]);
    return 1;
}


static int _print_ip(sock_udp_ep_t remote_rd)
{
    ipv6_addr_t addr;

    memcpy( &addr.u8[0], &remote_rd.addr.ipv6[0], sizeof(addr.u8));
    char addr_str[IPV6_ADDR_MAX_STR_LEN];
    printf("rd address :%s\n", ipv6_addr_to_str(addr_str, &addr, sizeof(addr_str)));
    printf("rd port:%d\n", remote_rd.port);
    return 0;
}

static void print_hex(char *str, uint8_t *buf, unsigned int size)
{
    printf("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        printf("%02X ", (unsigned)buf[i]);
    }
    puts("\n\n");
}


/**
 * @brief call back funtion for coap resource discovery
 *
 * @param status
 * @param remote_rd
 * @return int
 */
int discovery_callback_app(int status, sock_udp_ep_t remote_rd)
{
    switch (status) {
    case DISCOVERY_SUCCESS:
        /* resource discovery success */
        puts("resource discovery success\n");
        _print_ip(remote_rd);
        break;
    case DISCOVERY_FAILURE:
        /*resource discovery failure*/
        puts("resource discovery failure\n");
        break;
    default:
        break;
    }
    return status;
}

/**
 * @brief call back function for client registration with rd
 *
 * @param status
 * @return int
 */
int registration_callback_app(int status)
{
    switch (status) {
    case REGISTRATION_SUCCESS:
        /* client succesfully registered with rd */
        puts("registration success\n");
        break;
    case REGISTRATION_FAILURE:
        /*client  failed to register with rd*/
        puts("registration failure \n");
        break;
    default:
        break;
    }
    return status;
}


int lookup_callback_app(int status, wot_cert_t *node)
{
    (void)node;
    switch (status) {
    case LOOKUP_SUCCESS:
        /* successfully received lookup certificate from rd*/
        //ps();
        puts("lookup success\n");
        //printf("node name :%s\n", node->name);
        //print_hex("node public key : ", node->pubkey, (unsigned int)PUB_KEY_SIZE);
        #if !CONFIG_WOT_STORE_LOOKUP_CERT
        free(node);
        #endif
        break;
    case LOOKUP_FAILURE:
        /*failed get lookup certificate from rd*/
        puts("lookup failure \n");
        break;
    default:
        break;
    }
    return status;
}



int client_cmd_app(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    //for key exchange phase,key verification can be done using Pre-shared key,root certiciate,nfc,button press in wifi routers.
    //Admin can choose which method to use.These methods can be extented.
    char *verify_types[] = { "psk", "root", "oob" };

    if (argc == 1) {
        return _print_usage_cli(argv);
    }

    if (strcmp(argv[1], "-help") == 0) {
        //show help for commands
        return _print_usage_cli(argv);
    }
    else if (strcmp(argv[1], "-d") == 0) {
        if (argc != 2) {
            return _print_usage_cli(argv);
        }
        else {
            wot_discover_rd(discovery_callback_app);
        }
    }
    else if (strcmp(argv[1], "-r") == 0) {
        if (argc != 2) {
            return _print_usage_cli(argv);
        }

        if (wot_add_verify_method(CONFIG_WOT_AUTH_TYPE) != 0) {
            printf("failed to add verification method:%s\n", verify_types[CONFIG_WOT_AUTH_TYPE]);
            return 1;
        }
        else {
            wot_register_client(registration_callback_app);
        }
    }
    else if (strcmp(argv[1], "-l") == 0) {
        if (argc != 3) {
            return _print_usage_cli(argv);
        }
        else {
            wot_lookup_client(argv[2], lookup_callback_app);
        }
    }
    else {
        return _print_usage_cli(argv);
    }
    return 0;

}



