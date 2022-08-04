/**
 * @file wot_cbor.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-02-16
 *
 * @copyright Copyright (c) 2022
 *
 */
#include <string.h>
#include <stdlib.h>

#include "wot_cbor.h"
#include "keys.h"

#include "od.h"


/*hashing*/
#include "hashes/sha256.h"

/*ecc*/
#include "uECC.h"
#include "periph/hwrng.h"

/*aec*/
//#include "crypto/aes.h"
#include "crypto/ciphers.h"

#define ENABLE_DEBUG 1
#include "debug.h"

#if(POSIX_C_SOURCE < 200809L && _XOPEN_SOURCE < 700)
char *strndup(const char *s, size_t n)
{
    char *ret = malloc(n);
    strcpy(ret, s);
    return ret;
}
#endif


void vli_print_cbor(char *str, uint8_t *vli, unsigned int size)
{
    printf("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
    printf("\n");
}

/*USED in BOTH RD AND CLIENT TO CREATE CERTIFICATE TO BE SIGNED*/
int wot_get_cbor_certificate_csr(uint8_t *cbor_buf_csr, int buf_len)
{
    CborEncoder encoder;
    CborEncoder array_encoder;
    uint8_t cbor_len = 0;
    uint8_t pubkey_comp[PUB_KEY_COMPRESS_SIZE];

    DEBUG("\n\ncreating CBOR cert\n");
    cbor_encoder_init(&encoder, cbor_buf_csr, buf_len, 0);

    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    char *common_name = strndup(TEST_NAME, strlen(TEST_NAME));
    /*compressing pubkey*/
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uECC_compress(ecdsa_pub_key_new0, pubkey_comp, curve);

    /*encode common name*/
    cbor_encode_text_stringz(&array_encoder, common_name );
    /*encode public key*/
    cbor_encode_byte_string(&array_encoder, pubkey_comp, PUB_KEY_COMPRESS_SIZE);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf_csr);

    DEBUG("cbor cert size csr :%d\n", cbor_len);
    printf("c509 cert csr:");
    for (int i = 0; i < cbor_len; i++) {
        printf("%02X", cbor_buf_csr[i]);
    }
    printf("\n");
    return cbor_len;

}


/*USED IN RD to CREATE SIGNATURE USING PSK*/
int wot_create_signature_rd(uint8_t *cbor_buf_csr, int csr_len, uint8_t *signature)
{
    /*hashing+signature*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };

    sha256((uint8_t *)cbor_buf_csr, csr_len, hash_cert);

    printf("\nhash of cert:");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02X", hash_cert[i]);
    }
    printf("\n");

    /*encrypt hash using psk*/
    cipher_t cipher;

    if (cipher_init(&cipher, CIPHER_AES, psk_key, 32) < 0) {
        printf("aes init failed!\n");
    }
    if (cipher_encrypt(&cipher, hash_cert, signature) < 0) {
        printf("aes encryption failed!\n");
    }
    if (cipher_encrypt(&cipher, hash_cert + 16, signature + 16) < 0) {
        printf("aes encryption failed!\n");
    }
    else {
        printf("aes encryption success\n");
        od_hex_dump(signature, 32, 0);
    }

    return 0;

}

/*USED IN CLIENT TO CREATE SELF SIGN FOR CERTIFICATE*/
int wot_create_signature_client(uint8_t *cbor_buf_csr, int csr_len, uint8_t *signature)
{
    /*hashing+signature*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };

    sha256((uint8_t *)cbor_buf_csr, csr_len, hash_cert);

    printf("\nhash of cert:");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02X", hash_cert[i]);
    }
    printf("\n");

    const struct uECC_Curve_t *curve = uECC_secp256r1();

    if ((uECC_sign(ecdsa_priv_key_new0, hash_cert, sizeof(hash_cert), signature, curve)) != 1) {
        printf("\n uECC_sign() failed\n");
    }

    printf("\nself sign of hash:");
    //od_hex_dump(signature, 64, 0);

    for (int i = 0; i < 64; i++) {
        printf("%02X", signature[i]);
    }
    printf("\n");
    return 0;

}

/*USED IN RD TO CREATE RD'S CERTIFICATE*/
int wot_get_cbor_certificate_rd(uint8_t *buf)
{
    uint8_t cbor_len = 0;
    uint8_t cbor_len_csr = 0;
    uint8_t *cbor_buf_csr = (uint8_t *)calloc(64, sizeof(uint8_t));
    /*32 byte sign using psk*/
    uint8_t *signature = (uint8_t *)calloc(32, sizeof(uint8_t));

    /*get cbor cert to be signed*/
    cbor_len_csr = wot_get_cbor_certificate_csr(cbor_buf_csr, 64);
    /*sign using psk if rd*/
    wot_create_signature_rd(cbor_buf_csr, cbor_len_csr, signature);

    CborEncoder encoder;
    CborEncoder array_encoder;

    //TODO buf can also be dynamic,check size
    cbor_encoder_init(&encoder, buf, 128, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    cbor_encode_byte_string(&array_encoder, cbor_buf_csr, cbor_len_csr);
    cbor_encode_byte_string(&array_encoder, signature, 32);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, buf);

    printf("\nfinal cbor %d  :", cbor_len);
    for (int i = 0; i < cbor_len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");

    free(cbor_buf_csr);
    free(signature);
    return cbor_len;

}

/*USED IN CLIENT TO CREATE CLIENT'S CERTIFICATE*/
int wot_get_cbor_certificate_client(uint8_t *buf)
{

    uint8_t cbor_len = 0;
    uint8_t cbor_len_csr = 0;
    uint8_t *cbor_buf_csr = (uint8_t *)calloc(64, sizeof(uint8_t));
    /*64 byte sign using selfsign*/
    uint8_t *signature = (uint8_t *)calloc(64, sizeof(uint8_t));

    /*get cbor cert to be signed*/
    cbor_len_csr = wot_get_cbor_certificate_csr(cbor_buf_csr, 64);
    /*self sign*/
    wot_create_signature_client(cbor_buf_csr, cbor_len_csr, signature);

    CborEncoder encoder;
    CborEncoder array_encoder;

    cbor_encoder_init(&encoder, buf, 128, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    cbor_encode_byte_string(&array_encoder, cbor_buf_csr, cbor_len_csr);
    cbor_encode_byte_string(&array_encoder, signature, 64);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, buf);

    printf("\nfinal cbor %d  :", cbor_len);
    for (int i = 0; i < cbor_len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");

    free(cbor_buf_csr);
    free(signature);
    return cbor_len;

}

/*USED IN RD TO GET PUBLIC OF CLIENT TO VERIFY THE SIGNATURE USING uECC*/
int get_public_key_from_cert(uint8_t *cbor_buf_csr, uint8_t cert_len, uint8_t *pub_key)
{
    CborParser parser;
    CborValue it;
    CborValue recursed;

    uint8_t *pub_key_compress = (uint8_t *)calloc(33, sizeof(uint8_t));

    cbor_parser_init(cbor_buf_csr, cert_len, 0, &parser, &it);
    cbor_value_enter_container(&it, &recursed);
    cbor_value_advance(&recursed);
    CborType type = cbor_value_get_type(&recursed);
    if (type == CborByteStringType) {
        size_t len = 0;
        cbor_value_get_string_length(&recursed, &len);
        if (len != 33) {
            return 1;
        }
        else {
            cbor_value_copy_byte_string(&recursed, pub_key_compress, &len, &recursed);
            const struct uECC_Curve_t *curve = uECC_secp256r1();
            uECC_decompress(pub_key_compress, pub_key, curve);
        }

    }
    return 0;
}



/*USED IN RD CHECK IF THE RECEIVED CERTIFICATE IS VALID*/
int wot_check_client_cbor_cert_valid(uint8_t *cbor_buf_csr, uint8_t cert_len, uint8_t *signature,
                                     uint8_t sig_len)
{
    /*compute hash of certificate*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };

    sha256((uint8_t *)cbor_buf_csr, cert_len, hash_cert);
    /*get public key from cert for verification*/
    uint8_t *pub_key = (uint8_t *)calloc(PUB_KEY_SIZE, sizeof(uint8_t));
    get_public_key_from_cert(cbor_buf_csr, cert_len, pub_key);

    const struct uECC_Curve_t *curve = uECC_secp256r1();
    if ((uECC_verify(pub_key, hash_cert, sizeof(hash_cert), signature, curve)) != 1) {
        printf("\nuECC_verify() failed\n");
        return 1;
    }
    else {
        printf("\nuECC_verify() success\n");
    }
    free(pub_key);
    return 0;

}

/*USED IN CLIENT TO CHECK IF THE RECEIVED RD CER IS VALID*/
int wot_check_rd_cbor_cert_valid(uint8_t *cbor_buf_csr, uint8_t cert_len, uint8_t *signature,
                                 uint8_t sig_len)
{

    /*decrypting signature to get hash of cert*/
    cipher_t cipher;
    uint8_t *sig_decrypt = (uint8_t *)calloc(32, sizeof(uint8_t));

    if (cipher_init(&cipher, CIPHER_AES, psk_key, 32) < 0) {
        printf("aes init failed!\n");
    }

    if (cipher_decrypt(&cipher, signature, sig_decrypt) < 0) {
        printf("aes decryption failed!\n");
    }

    if (cipher_decrypt(&cipher, signature + 16, sig_decrypt + 16) < 0) {
        printf("aes decryption failed!\n");
    }

    /*compute hash of certificate*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };
    sha256((uint8_t *)cbor_buf_csr, cert_len, hash_cert);

    vli_print_cbor("decrypted signature =     ", sig_decrypt, 32);
    vli_print_cbor("calculated hash =   ", hash_cert, (unsigned int)sizeof(hash_cert));

    /*check if certificate is valid*/
    if (memcmp(sig_decrypt, hash_cert, 32) != 0) {
        printf("invalid certificate\n");
        return 1;
    }
    else {
        printf("valid certificate\n");
    }
    free(sig_decrypt);

    return 0;

}

/*USED IN CLIENT TO PARSE RECEIVED RD CERT,FIRST ENTRY POINT FROM COAP*/
CborError wot_parse_cbor_cert_rd(uint8_t *payload, uint16_t payload_len)
{
    CborParser parser;
    CborValue it;
    size_t cert_len = 0;
    size_t sig_len = 0;
    uint8_t *cbor_buf_csr = NULL;
    uint8_t *signature = NULL;

    CborError err = cbor_parser_init(payload, payload_len, 0, &parser, &it);

    if (err) {
        printf("error parsing cbor rd certificate....\n");
        return err;
    }

    CborType type = cbor_value_get_type(&it);
    if (type == CborArrayType) {
        CborValue recursed;
        err = cbor_value_enter_container(&it, &recursed);
        if (err) {
            printf("failed to enter container....\n");
            return err;
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            cbor_value_get_string_length(&recursed, &cert_len);
            printf("cbor _cer len:%d\n", cert_len);
            cbor_buf_csr = (uint8_t *)calloc(cert_len, sizeof(uint8_t));
            err = cbor_value_copy_byte_string(&recursed, cbor_buf_csr, &cert_len,
                                              &recursed);
            if (err) {
                printf("failed to copy certificate....\n");
                return err;
            }
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            cbor_value_get_string_length(&recursed, &sig_len);
            printf("signature len:%d\n", sig_len);
            signature = (uint8_t *)calloc(sig_len, sizeof(uint8_t));
            err = cbor_value_copy_byte_string(&recursed, signature, &sig_len,
                                              &recursed);
            if (err) {
                printf("failed to copy signature....\n");
                return err;
            }
        }
        vli_print_cbor("certificate =     ", cbor_buf_csr, (unsigned int)cert_len);
        vli_print_cbor("signature =   ", signature, (unsigned int)sig_len);

        int ret = wot_check_rd_cbor_cert_valid(cbor_buf_csr, cert_len, signature, sig_len);

        if (ret != 0) {
            printf("invalid certificate\n");
            return 1;
        }
        else {
            printf("valid certificate\n");
            wot_store_cert(cbor_buf_csr, cert_len);

        }
        free(cbor_buf_csr);
        free(signature);
    }
    return 0;

}

/*USED IN RD TO PARSE RECEIVED CLIENT CERT,FIRST ENTRY POINT FROM COAP*/
CborError wot_parse_cbor_cert_client(uint8_t *payload, uint16_t payload_len)
{
    CborParser parser;
    CborValue it;
    size_t cert_len = 0;
    size_t sig_len = 0;
    uint8_t *cbor_buf_csr = NULL;
    uint8_t *signature = NULL;

    CborError err = cbor_parser_init(payload, payload_len, 0, &parser, &it);

    if (err) {
        printf("error parsing cbor rd certificate....\n");
        return err;
    }

    CborType type = cbor_value_get_type(&it);
    if (type == CborArrayType) {
        CborValue recursed;
        err = cbor_value_enter_container(&it, &recursed);
        if (err) {
            printf("failed to enter container....\n");
            return err;
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            cbor_value_get_string_length(&recursed, &cert_len);
            printf("cbor _cer len:%d\n", cert_len);
            cbor_buf_csr = (uint8_t *)calloc(cert_len, sizeof(uint8_t));
            err = cbor_value_copy_byte_string(&recursed, cbor_buf_csr, &cert_len,
                                              &recursed);
            if (err) {
                printf("failed to copy certificate....\n");
                return err;
            }
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            cbor_value_get_string_length(&recursed, &sig_len);
            printf("signature len:%d\n", sig_len);
            signature = (uint8_t *)calloc(sig_len, sizeof(uint8_t));
            err = cbor_value_copy_byte_string(&recursed, signature, &sig_len,
                                              &recursed);
            if (err) {
                printf("failed to copy signature....\n");
                return err;
            }
        }
        vli_print_cbor("certificate =     ", cbor_buf_csr, (unsigned int)cert_len);
        vli_print_cbor("signature =   ", signature, (unsigned int)sig_len);

        int ret = wot_check_client_cbor_cert_valid(cbor_buf_csr, cert_len, signature, sig_len);

        if (ret != 0) {
            printf("invalid certificate\n");
            return 1;
        }
        else {
            printf("valid certificate\n");
            wot_store_cert(cbor_buf_csr, cert_len);

        }
        free(cbor_buf_csr);
        free(signature);
    }
    return 0;

}

/*USED IN BOTH RD AND CLIENT TO STORE CERTIFICATE*/
CborError wot_store_cert(uint8_t *payload, uint16_t payload_len)
{
    CborParser parser;
    CborValue it;

    uint8_t *pub_buf = (uint8_t *)calloc(PUB_KEY_SIZE, sizeof(uint8_t));
    uint8_t *pub_buf_compress = (uint8_t *)calloc(33, sizeof(uint8_t));
    char *common_name = (char *)calloc(NAME_MAX_LEN, sizeof(char));
    size_t common_name_len = 0;

    CborError err = cbor_parser_init(payload, payload_len, 0, &parser, &it);

    if (err) {
        printf("error parsing cbor certificate....\n");
        return err;
    }
    CborType type = cbor_value_get_type(&it);
    if (type == CborArrayType) {
        CborValue recursed;
        err = cbor_value_enter_container(&it, &recursed);
        if (err) {
            return err;
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborTextStringType) {
            cbor_value_get_string_length(&recursed, &common_name_len);
            err = cbor_value_copy_text_string(&recursed, common_name, &common_name_len,
                                              &recursed);
            if (err) {
                return err;
            }
            printf("common name:%s\n", common_name);
        }
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            size_t len = 0;
            cbor_value_get_string_length(&recursed, &len);
            err = cbor_value_copy_byte_string(&recursed, pub_buf_compress, &len, &recursed);
            if (err) {
                return err;
            }

            const struct uECC_Curve_t *curve = uECC_secp256r1();
            uECC_decompress(pub_buf_compress, pub_buf, curve);

            printf("public key:");
            for (int i = 0; i < (int)PUB_KEY_SIZE; i++) {
                printf("%02X", pub_buf[i]);
            }
            printf("\n");
        }
    }
    /*----------------------TODO store in list-------------*/
    free(pub_buf);
    free(pub_buf_compress);
    free(common_name);
    return CborNoError;
}



int wot_get_test_cert(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uint8_t buf[CBOR_BUFSIZE] = { 0 };
    uint8_t buf_len = wot_get_cbor_certificate_rd(buf);
    //uint8_t buf_len = wot_get_cbor_certificate_client(buf);

    wot_parse_cbor_cert_rd(buf, buf_len);
    //wot_parse_cbor_cert_client(buf, buf_len);
    return 0;

}
