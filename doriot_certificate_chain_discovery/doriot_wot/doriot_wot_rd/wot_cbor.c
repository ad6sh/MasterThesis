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

#include "xtimer.h"

#if CONFIG_WOT_USE_CRYPTO_CELL
#if IS_ACTIVE(MODULE_LIB_CRYPTOCELL)
#include "cryptocell_util.h"
#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/crys_ecpki_build.h"
#include "cryptocell_incl/crys_ecpki_ecdsa.h"
#include "cryptocell_incl/crys_ecpki_domain.h"
extern CRYS_RND_State_t *rndState_ptr;
#define CRYPTO_CELL_PUB_KEY_SIZE 65
#endif
#endif

#include "wot_cbor.h"
#include "wot_list.h"
#include "wot_key.h"

#define ENABLE_DEBUG 0
#include "debug.h"

#if (POSIX_C_SOURCE < 200809L && _XOPEN_SOURCE < 700)
char *strndup(const char *s, size_t n)
{
    char *ret = malloc(n);

    strcpy(ret, s);
    return ret;
}
#endif

void print_hex(char *str, uint8_t *buf, unsigned int size)
{
    DEBUG("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        DEBUG("%02X ", (unsigned)buf[i]);
    }
    DEBUG("\n\n");
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

    //char *common_name = strndup(CONFIG_WOT_RD_COMMON_NAME, strlen(CONFIG_WOT_RD_COMMON_NAME));
    /*compressing pubkey*/
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    //uECC_compress(ecdsa_pub_key_rd, pubkey_comp, curve);
    uECC_compress(credentials_module.public_key, pubkey_comp, curve);
    /*encode common name*/
    //cbor_encode_text_stringz(&array_encoder, common_name );
    cbor_encode_text_stringz(&array_encoder, CONFIG_WOT_RD_COMMON_NAME );
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
    if (cipher_init(&cipher, CIPHER_AES, credentials_module.psk_key, PSK_SIGN_LEN) < 0) {
        DEBUG("aes init failed!\n");
    }
    if (cipher_encrypt(&cipher, hash_cert, signature) < 0) {
        DEBUG("aes encryption failed!\n");
    }
    if (cipher_encrypt(&cipher, hash_cert + 16, signature + 16) < 0) {
        DEBUG("aes encryption failed!\n");
    }
    else {
        DEBUG("aes encryption success\n");
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


#if CONFIG_WOT_USE_CRYPTO_CELL
int _set_crypto_cell_public_key(CRYS_ECPKI_UserPublKey_t *crypto_pub_key, uint8_t *pub_key)
{
    //uint8_t pub_key_local[65];
    uint8_t *pub_key_local = (uint8_t *)calloc(CRYPTO_CELL_PUB_KEY_SIZE, sizeof(uint8_t));
    pub_key_local[0] = 0x04; //Uncompressed pub key
    memcpy(pub_key_local + 1, pub_key, PUB_KEY_SIZE);
    
    CRYS_ECPKI_Domain_t *pDomain = (CRYS_ECPKI_Domain_t *)CRYS_ECPKI_GetEcDomain(
        CRYS_ECPKI_DomainID_secp256r1);
    CRYS_ECPKI_BUILD_TempData_t pTempBuff;

    int ret = _DX_ECPKI_BuildPublKey(pDomain, pub_key_local, (uint32_t)CRYPTO_CELL_PUB_KEY_SIZE, 0, crypto_pub_key, &pTempBuff);

    if (ret != CRYS_OK) {
        DEBUG("failed to copy crypto pub key");
        free(pub_key_local);
        return 1;
    }
    else {
        DEBUG("copied crypto pub key\n");
        free(pub_key_local);
    }
    return 0;
}
#endif




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

    /*get public key from cert for verification*/
    uint8_t *pub_key = (uint8_t *)calloc(PUB_KEY_SIZE, sizeof(uint8_t));
    _get_public_key_from_cert(cbor_buf_csr, cert_len, pub_key);
    
    #if CONFIG_WOT_USE_CRYPTO_CELL
    int ret = 0;
    CRYS_ECDSA_VerifyUserContext_t VerifyUserContext;
    CRYS_ECPKI_UserPublKey_t UserPublKey;
    _set_crypto_cell_public_key(&UserPublKey, pub_key);

    cryptocell_enable();
    ret =  CRYS_ECDSA_Verify(&VerifyUserContext, &UserPublKey, CRYS_ECPKI_HASH_SHA256_mode,
                             signature, ECC_SIGN_LEN, cbor_buf_csr, cert_len);
    cryptocell_disable();
    if (ret != SA_SILIB_RET_OK) {
        DEBUG("CRYS_ECDSA_Verify failed with 0x%x \n", ret);
        return 1;
    }
    else {
        DEBUG("verified with crypto cell public key,valid certificate\n");
        return 0;
    }
    #else
    /*compute hash of certificate*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };
    sha256((uint8_t *)cbor_buf_csr, cert_len, hash_cert);
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    if ((uECC_verify(pub_key, hash_cert, sizeof(hash_cert), signature, curve)) != 1) {
        DEBUG("invalid certificate\n");
        return 1;
    }
    else {
        DEBUG("verified with public key,valid certificate\n");
    }
    #endif
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
            DEBUG("common name : %s\n", common_name);
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
        DEBUG("error parsing cbor rd certificate....\n");
        return err;
    }

    CborType type = cbor_value_get_type(&it);
    if (type == CborArrayType) {
        CborValue recursed;
        err = cbor_value_enter_container(&it, &recursed);
        if (err) {
            DEBUG("failed to enter container....\n");
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
                DEBUG("failed to copy certificate....\n");
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
                DEBUG("failed to copy signature....\n");
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
/*--------------------------lookup interface----------------------------*/

extern uint32_t count_lkup;
uint32_t crypto_start_time[100];
uint32_t crypto_end_time[100]; 

#if CONFIG_WOT_USE_CRYPTO_CELL
int _set_crypto_cell_private_key(CRYS_ECPKI_UserPrivKey_t *crypto_pvt_key)
{
    int ret = 0;
    CRYS_ECPKI_Domain_t *pDomain = (CRYS_ECPKI_Domain_t *)CRYS_ECPKI_GetEcDomain(
        CRYS_ECPKI_DomainID_secp256r1);

    ret = CRYS_ECPKI_BuildPrivKey(pDomain, credentials_module.private_key, (uint32_t)PVT_KEY_SIZE,
                                  crypto_pvt_key);
    if (ret != CRYS_OK) {
        DEBUG("failed to crypt private key\n");
        return 1;
    }
    else {
        DEBUG("copied crypt private key\n");
    }
    return 0;

}
#endif



/**
 * @brief sign the client cert using rd's private key
 *
 * @param cbor_buf_csr
 * @param csr_len
 * @param signature
 * @return int
 */
static int _wot_create_signature_lookup(uint8_t *cbor_buf_csr, int csr_len, uint8_t *signature)
{
    #if CONFIG_WOT_USE_CRYPTO_CELL
    int ret = 0;
    CRYS_ECDSA_SignUserContext_t SignUserContext;
    SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc = CRYS_RND_GenerateVector;
    CRYS_ECPKI_UserPrivKey_t UserPrivKey;
    CRYS_ECDH_TempData_t signOutBuff;
    uint32_t ecdsa_sig_size = ECC_SIGN_LEN;
    _set_crypto_cell_private_key(&UserPrivKey);
     crypto_start_time[count_lkup]=xtimer_now_usec();
    cryptocell_enable();

    ret = CRYS_ECDSA_Sign(rndState_ptr, rndGenerateVectFunc,
                          &SignUserContext, &UserPrivKey, CRYS_ECPKI_HASH_SHA256_mode, cbor_buf_csr,
                          (uint32_t)csr_len, (uint8_t *)&signOutBuff, &ecdsa_sig_size);
    cryptocell_disable();
    crypto_end_time[count_lkup]=xtimer_now_usec();
    if (ret != SA_SILIB_RET_OK) {
        DEBUG("CRYS_ECDSA_Sign failed with 0x%x \n", ret);
        return 1;
    }
    else {
        DEBUG("CRYS_ECDSA_Sign success\n");
        memcpy(signature, (uint8_t *)&signOutBuff, ECC_SIGN_LEN);
        return 0;
    }

    #else
    /*hashing+signature*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };
    sha256((uint8_t *)cbor_buf_csr, csr_len, hash_cert);
    print_hex("hash of client csr : ", hash_cert, (unsigned int)SHA256_DIGEST_LENGTH);

    const struct uECC_Curve_t *curve = uECC_secp256r1();
    crypto_start_time[count_lkup]=xtimer_now_usec();
    if ((uECC_sign(credentials_module.private_key, hash_cert, sizeof(hash_cert), signature,
                   curve)) != 1) {
        DEBUG("\nfailed to sign with private key\n");
    }
    crypto_end_time[count_lkup]=xtimer_now_usec();
    #endif
    print_hex("selfsign client hash : ", signature, ECC_SIGN_LEN);
    return 0;

}

/**
 * @brief create clients cbor certificate during lookup
 *
 * @param cbor_buf_csr
 * @param name
 * @param buf_len
 * @return int
 */
static int _wot_get_cbor_certificate_csr_lookup(uint8_t *cbor_buf_csr, char *name, int buf_len)
{
    CborEncoder encoder;
    CborEncoder array_encoder;
    uint8_t cbor_len = 0;
    uint8_t pubkey_comp[PUB_KEY_COMPRESS_SIZE];

    cbor_encoder_init(&encoder, cbor_buf_csr, buf_len, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    /*compressing pubkey*/
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    /*search for node ,get public key*/
    wot_cert_t *node = wot_cert_get(name);
    uECC_compress(node->pubkey, pubkey_comp, curve);
    /*encode common name*/
    cbor_encode_text_stringz(&array_encoder, name );
    /*encode public key*/
    cbor_encode_byte_string(&array_encoder, pubkey_comp, PUB_KEY_COMPRESS_SIZE);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf_csr);

    DEBUG("cbor cert size lookup csr :%d\n", cbor_len);
    print_hex("c509 lookup cert csr : ", cbor_buf_csr, (unsigned int)cbor_len);

    return cbor_len;
}


/**
 * @brief  function to create cbor cert responce while lookup
 *
 * @param buf
 * @param name
 * @return int
 */
int wot_get_cbor_certificate_lookup(uint8_t *buf, char *name)
{
    uint8_t cbor_len = 0;
    uint8_t cbor_len_csr = 0;
    uint8_t *cbor_buf_csr = (uint8_t *)calloc(64, sizeof(uint8_t));
    /*64 byte sign using rd's private key*/
    uint8_t *signature = (uint8_t *)calloc(ECC_SIGN_LEN, sizeof(uint8_t));

    /*get cbor cert to be signed*/
    cbor_len_csr = _wot_get_cbor_certificate_csr_lookup(cbor_buf_csr, name, 64);
    /*sign using psk if rd*/
    _wot_create_signature_lookup(cbor_buf_csr, cbor_len_csr, signature);

    CborEncoder encoder;
    CborEncoder array_encoder;

    cbor_encoder_init(&encoder, buf, CBOR_BUFSIZE, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 3);
    /*cbor array of [rd_name,client_cbor_cert,signature]*/
    cbor_encode_text_stringz(&array_encoder, CONFIG_WOT_RD_COMMON_NAME );
    cbor_encode_byte_string(&array_encoder, cbor_buf_csr, cbor_len_csr);
    cbor_encode_byte_string(&array_encoder, signature, ECC_SIGN_LEN);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, buf);

    print_hex("final client cbor : ", buf, (unsigned int)cbor_len);

    free(cbor_buf_csr);
    free(signature);
    return cbor_len;

}



int parse_look_up_request(uint8_t *payload, uint16_t payload_len, char *client_name,
                          char *lookup_name)
{
    CborParser parser;
    CborValue it;
    CborValue client;
    CborValue lookup;
    size_t client_common_name_len = 0;
    size_t lookup_common_name_len = 0;
    CborError err = cbor_parser_init(payload, payload_len, 0, &parser, &it);

    if (cbor_value_is_map(&it)) {
        cbor_value_map_find_value(&it, "client", &client);
        cbor_value_get_string_length(&client, &client_common_name_len);
        cbor_value_copy_text_string(&client, client_name, &client_common_name_len, NULL);
        DEBUG("client name : %s\n", client_name);

        cbor_value_map_find_value(&it, "id", &lookup);
        cbor_value_get_string_length(&lookup, &lookup_common_name_len);
        cbor_value_copy_text_string(&lookup, lookup_name, &lookup_common_name_len, NULL);
        DEBUG("lookup name : %s\n", lookup_name);

    }
    return 0;
}
