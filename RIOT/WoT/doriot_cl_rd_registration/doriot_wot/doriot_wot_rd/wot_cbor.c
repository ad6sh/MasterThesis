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

#include "od.h"
#include "hashes/sha256.h"
#include "uECC.h"
#include "periph/hwrng.h"
#include "crypto/ciphers.h"

#include "wot_cbor.h"
#include "wot_list.h"
#include "wot_key.h"

#define ENABLE_DEBUG 0
#include "debug.h"

void print_hex(char *str, uint8_t *buf, unsigned int size)
{
    printf("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        printf("%02X ", (unsigned)buf[i]);
    }
    printf("\n\n");
}

#ifdef CONFIG_WOT_RD_COMMON_NAME
/**
 * @brief function to get rd's to be signed certificate
 * 
 * @param cbor_buf_csr 
 * @param buf_len 
 * @return int 
 */
static int _wot_get_cbor_certificate_csr(uint8_t *cbor_buf_csr, int buf_len)
{
    CborEncoder encoder;
    CborEncoder array_encoder;
    uint8_t cbor_len = 0;
    uint8_t pubkey_comp[PUB_KEY_COMPRESS_SIZE];

    cbor_encoder_init(&encoder, cbor_buf_csr, buf_len, 0);

    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    char *common_name = strndup(CONFIG_WOT_RD_COMMON_NAME, strlen(CONFIG_WOT_RD_COMMON_NAME));
    /*compressing pubkey*/
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uECC_compress(ecdsa_pub_key_rd, pubkey_comp, curve);

    /*encode common name*/
    cbor_encode_text_stringz(&array_encoder, common_name );
    /*encode public key*/
    cbor_encode_byte_string(&array_encoder, pubkey_comp, PUB_KEY_COMPRESS_SIZE);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf_csr);

    DEBUG("cbor cert size csr :%d\n", cbor_len);
    print_hex("c509 rd cert csr : ", cbor_buf_csr, (unsigned int)cbor_len);

    return cbor_len;
}
#endif /*CONFIG_WOT_RD_COMMON_NAME*/


/**
 * @brief function to create signature using psk
 * 
 * @param cbor_buf_csr 
 * @param csr_len 
 * @param signature 
 * @return int 
 */
static int _wot_create_signature_rd(uint8_t *cbor_buf_csr, int csr_len, uint8_t *signature)
{
    /*hashing+signature*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };

    sha256((uint8_t *)cbor_buf_csr, csr_len, hash_cert);

    print_hex("hash rd csr : ", hash_cert, (unsigned int)SHA256_DIGEST_LENGTH);

    /*encrypt hash using psk*/
    cipher_t cipher;

    if (cipher_init(&cipher, CIPHER_AES, psk_key, PSK_SIGN_LEN) < 0) {
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
        print_hex("psk signed rd hash : ", signature, PSK_SIGN_LEN);
    }

    return 0;

}


int wot_get_cbor_certificate_rd(uint8_t *buf)
{
    uint8_t cbor_len = 0;
    uint8_t cbor_len_csr = 0;
    uint8_t *cbor_buf_csr = (uint8_t *)calloc(64, sizeof(uint8_t));
    /*32 byte sign using psk*/
    uint8_t *signature = (uint8_t *)calloc(PSK_SIGN_LEN, sizeof(uint8_t));

    /*get cbor cert to be signed*/
    cbor_len_csr = _wot_get_cbor_certificate_csr(cbor_buf_csr, 64);
    /*sign using psk if rd*/
    _wot_create_signature_rd(cbor_buf_csr, cbor_len_csr, signature);

    CborEncoder encoder;
    CborEncoder array_encoder;

    cbor_encoder_init(&encoder, buf, CBOR_BUFSIZE, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    cbor_encode_byte_string(&array_encoder, cbor_buf_csr, cbor_len_csr);
    cbor_encode_byte_string(&array_encoder, signature, PSK_SIGN_LEN);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, buf);

    print_hex("final rd cbor : ", buf, (unsigned int)cbor_len);

    free(cbor_buf_csr);
    free(signature);
    return cbor_len;

}


/**
 * @brief Get the public key from cert object to verify the signature using uECC
 * 
 * @param cbor_buf_csr 
 * @param cert_len 
 * @param pub_key 
 * @return int 
 */
static int _get_public_key_from_cert(uint8_t *cbor_buf_csr, uint8_t cert_len, uint8_t *pub_key)
{
    CborParser parser;
    CborValue it;
    CborValue recursed;

    uint8_t *pub_key_compress = (uint8_t *)calloc(PUB_KEY_COMPRESS_SIZE, sizeof(uint8_t));

    cbor_parser_init(cbor_buf_csr, cert_len, 0, &parser, &it);
    cbor_value_enter_container(&it, &recursed);
    cbor_value_advance(&recursed);
    CborType type = cbor_value_get_type(&recursed);
    if (type == CborByteStringType) {
        size_t len = 0;
        cbor_value_get_string_length(&recursed, &len);
        if (len != PUB_KEY_COMPRESS_SIZE) {
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


/**
 * @brief function to check is the received client cert is valid
 * 
 * @param cbor_buf_csr 
 * @param cert_len 
 * @param signature 
 * @param sig_len 
 * @return int 
 */
int _wot_check_client_cbor_cert_valid(uint8_t *cbor_buf_csr, uint8_t cert_len, uint8_t *signature,
                                     uint8_t sig_len)
{
    /*compute hash of certificate*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };

    sha256((uint8_t *)cbor_buf_csr, cert_len, hash_cert);
    /*get public key from cert for verification*/
    uint8_t *pub_key = (uint8_t *)calloc(PUB_KEY_SIZE, sizeof(uint8_t));
    _get_public_key_from_cert(cbor_buf_csr, cert_len, pub_key);

    const struct uECC_Curve_t *curve = uECC_secp256r1();
    if ((uECC_verify(pub_key, hash_cert, sizeof(hash_cert), signature, curve)) != 1) {
        printf("invalid certificate\n");
        return 1;
    }
    else {
        printf("verified with public key,valid certificate\n");
    }
    free(pub_key);
    return 0;

}


/**
 * @brief stores the certificate to list
 * 
 * @param payload 
 * @param payload_len 
 * @return CborError 
 */
static CborError _wot_store_cert(uint8_t *payload, uint16_t payload_len)
{
    CborParser parser;
    CborValue it;

    uint8_t *pub_buf = (uint8_t *)calloc(PUB_KEY_SIZE, sizeof(uint8_t));
    uint8_t *pub_buf_compress = (uint8_t *)calloc(PUB_KEY_COMPRESS_SIZE, sizeof(uint8_t));
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
            printf("common name : %s\n", common_name);
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

            print_hex("client public key:", pub_buf, (unsigned int)PUB_KEY_SIZE);

        }
    }
    //wot_cert_t *node = wot_cert_add(common_name, (int)common_name_len, pub_buf);
    wot_cert_t *node = wot_cert_add(common_name, strlen(common_name), pub_buf);
    DEBUG("stored node name : %s\n", node->name);
    free(pub_buf);
    free(pub_buf_compress);
    free(common_name);
    return CborNoError;
}


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
            DEBUG("cbor cert len:%d\n", cert_len);
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
            DEBUG("signature len : %d\n", sig_len);
            signature = (uint8_t *)calloc(sig_len, sizeof(uint8_t));
            err = cbor_value_copy_byte_string(&recursed, signature, &sig_len,
                                              &recursed);
            if (err) {
                printf("failed to copy signature....\n");
                return err;
            }
        }
        print_hex("certificate : ", cbor_buf_csr, (unsigned int)cert_len);
        print_hex("signature : ", signature, (unsigned int)sig_len);

        int ret = _wot_check_client_cbor_cert_valid(cbor_buf_csr, cert_len, signature, sig_len);

        if (ret != 0) {
            DEBUG("invalid certificate\n");
            return 1;
        }
        else {
            DEBUG("valid certificate\n");
            _wot_store_cert(cbor_buf_csr, cert_len);

        }
        free(cbor_buf_csr);
        free(signature);
    }
    return 0;

}

