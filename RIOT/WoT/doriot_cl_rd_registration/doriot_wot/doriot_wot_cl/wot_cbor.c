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

#ifdef CONFIG_WOT_CL_COMMON_NAME
/**
 * @brief create the cbor certificate to be signed
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

    char *common_name = strndup(CONFIG_WOT_CL_COMMON_NAME, strlen(CONFIG_WOT_CL_COMMON_NAME));
    /*compressing pubkey*/
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uECC_compress(ecdsa_pub_key_client, pubkey_comp, curve);

    /*encode common name*/
    cbor_encode_text_stringz(&array_encoder, common_name );
    /*encode public key*/
    cbor_encode_byte_string(&array_encoder, pubkey_comp, PUB_KEY_COMPRESS_SIZE);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf_csr);

    print_hex("c509 client csr : ", cbor_buf_csr, (unsigned int)cbor_len);

    return cbor_len;
}
#endif /*CONFIG_WOT_CL_COMMON_NAME*/


/**
 * @brief function create signature of client certficate,self signed using clients private key
 *
 * @param cbor_buf_csr
 * @param csr_len
 * @param signature
 * @return int
 */
static int _wot_create_signature_client(uint8_t *cbor_buf_csr, int csr_len, uint8_t *signature)
{
    /*hashing+signature*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };

    sha256((uint8_t *)cbor_buf_csr, csr_len, hash_cert);

    print_hex("hash of client csr : ", hash_cert, (unsigned int)SHA256_DIGEST_LENGTH);

    const struct uECC_Curve_t *curve = uECC_secp256r1();

    if ((uECC_sign(ecdsa_priv_key_client, hash_cert, sizeof(hash_cert), signature, curve)) != 1) {
        printf("\nfailed to sign with private key\n");
    }

    print_hex("selfsign client hash : ", signature, SIG_SELF_SIGN_LEN);
    return 0;

}


int wot_get_cbor_certificate_client(uint8_t *buf)
{

    uint8_t cbor_len = 0;
    uint8_t cbor_len_csr = 0;
    uint8_t *cbor_buf_csr = (uint8_t *)calloc(64, sizeof(uint8_t));
    /*64 byte sign using selfsign*/
    uint8_t *signature = (uint8_t *)calloc(SIG_SELF_SIGN_LEN, sizeof(uint8_t));

    /*get cbor cert to be signed*/
    cbor_len_csr = _wot_get_cbor_certificate_csr(cbor_buf_csr, 64);
    /*self sign*/
    _wot_create_signature_client(cbor_buf_csr, cbor_len_csr, signature);

    CborEncoder encoder;
    CborEncoder array_encoder;

    cbor_encoder_init(&encoder, buf, CBOR_BUFSIZE, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    cbor_encode_byte_string(&array_encoder, cbor_buf_csr, cbor_len_csr);
    cbor_encode_byte_string(&array_encoder, signature, SIG_SELF_SIGN_LEN);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, buf);

    print_hex("final client cbor :", buf, (unsigned int)cbor_len);

    free(cbor_buf_csr);
    free(signature);
    return cbor_len;

}


/**
 * @brief function to check if received rd certificate is valid using psk
 * 
 * @param cbor_buf_csr 
 * @param cert_len 
 * @param signature 
 * @param sig_len 
 * @return int 
 */
static int _wot_check_rd_cbor_cert_valid(uint8_t *cbor_buf_csr, uint8_t cert_len, uint8_t *signature,
                                 uint8_t sig_len)
{

    /*decrypting signature to get hash of cert*/
    cipher_t cipher;
    uint8_t *sig_decrypt = (uint8_t *)calloc(PSK_SIGN_LEN, sizeof(uint8_t));

    if (cipher_init(&cipher, CIPHER_AES, psk_key, PSK_SIGN_LEN) < 0) {
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

    print_hex("decrypted signature : ", sig_decrypt, PSK_SIGN_LEN);
    print_hex("calculated hash : ", hash_cert, (unsigned int)sizeof(hash_cert));

    /*check if certificate is valid*/
    if (memcmp(sig_decrypt, hash_cert, PSK_SIGN_LEN) != 0) {
        printf("invalid certificate\n");
        return 1;
    }
    else {
        printf("valid certificate\n");
    }
    free(sig_decrypt);

    return 0;

}

/**
 * @brief function to store rd's certificate in list
 * 
 * @param payload 
 * @param payload_len 
 * @return CborError 
 */
CborError _wot_store_cert(uint8_t *payload, uint16_t payload_len)
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
            printf("rd common name : %s\n", common_name);
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

            print_hex("rd public key : ", pub_buf, (unsigned int)PUB_KEY_SIZE);

        }
    }
    //wot_cert_t *node = wot_cert_add(common_name, (int)common_name_len, pub_buf);
    wot_cert_t *node = wot_cert_add(common_name, strlen(common_name), pub_buf);
    DEBUG("stored node name:%s\n", node->name);

    free(pub_buf);
    free(pub_buf_compress);
    free(common_name);
    return CborNoError;
}

/**
 * @brief parse received rd certificate
 * 
 * @param payload 
 * @param payload_len 
 * @return CborError 
 */
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
            DEBUG("cbor rd cert len:%d\n", cert_len);
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
            DEBUG("signature len:%d\n", sig_len);
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

        int ret = _wot_check_rd_cbor_cert_valid(cbor_buf_csr, cert_len, signature, sig_len);

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


