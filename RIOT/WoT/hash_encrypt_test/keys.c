#include <stdio.h>
#include <string.h>
#include "uECC.h"
#include "periph/hwrng.h"

#include "keys.h"


uint8_t ecdsa_priv_key[32] = { 0 };
uint8_t ecdsa_pub_key[64] = { 0 };






void vli_print(char *str, uint8_t *vli, unsigned int size)
{
    printf("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
    printf("\n");
}


int wot_create_keys(void )
{

    uint8_t private[32];
    uint8_t public[64];


    const struct uECC_Curve_t *curve = uECC_secp256r1();
    int curve_size = uECC_curve_private_key_size(curve);
    int public_key_size = uECC_curve_public_key_size(curve);

    printf("pubkey size:%d,pvtkey size:%d\n", public_key_size, curve_size);

    if (!uECC_make_key(ecdsa_pub_key, ecdsa_priv_key, curve)) {
        printf("uECC_make_key() failed\n");
    }


    return 0;

}


int wot_print_keys(void )
{
    printf("public :");
    for (int i = 0; i < 64; i++) {
        printf("0x%02X,", ecdsa_pub_key[i]);
    }
    printf("\n");

    printf("private :");
    for (int i = 0; i < 32; i++) {
        printf("0x%02X,", ecdsa_priv_key[i]);
    }
    printf("\n");

    return 0;

}


int wot_create_k(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    wot_create_keys();
    return 0;

}


int wot_print_k(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    wot_print_keys();
    return 0;
}


int wot_print_cp(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uint8_t compressed_point[33];
    uint8_t decompressed_point[64];
    const struct uECC_Curve_t *curve = uECC_secp256r1();

    /* compress and decompress point */
    uECC_compress(ecdsa_pub_key_new0, compressed_point, curve);
    uECC_decompress(compressed_point, decompressed_point, curve);

    if (memcmp(ecdsa_pub_key_new0, decompressed_point, sizeof(ecdsa_pub_key_new0)) != 0) {
        printf("Original and decompressed points are not identical!\n");
    }
    else {
        printf("Original and decompressed points are identical!\n");
        vli_print("Original point =     ", ecdsa_pub_key_new0, sizeof(ecdsa_pub_key_new0));
        vli_print("Compressed point =   ", compressed_point, sizeof(compressed_point));
        vli_print("Decompressed point = ", decompressed_point, sizeof(decompressed_point));
    }
    printf("\n");

    return 0;
}
