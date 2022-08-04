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
//#define __STDC_FORMAT_MACROS
//#include <inttypes.h>

#include <string.h>
#include <stdlib.h>

#include "od.h"
#include "hashes/sha256.h"
#include "uECC.h"
#include "periph/hwrng.h"
#include "crypto/ciphers.h"


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


#include "xtimer.h"

#include "wot_cbor.h"
#include "wot_list.h"
#include "wot_key.h"

#define ENABLE_DEBUG 1
#include "debug.h"

#if (POSIX_C_SOURCE < 200809L && _XOPEN_SOURCE < 700)
char *strndup(const char *s, size_t n)
{
    char *ret = malloc(n);

    strcpy(ret, s);
    return ret;
}
#endif

extern int (*lookup_callback)(int, wot_cert_t *);
uint32_t c509_start_time;
uint32_t c509_end_time;


void print_hex(char *str, uint8_t *buf, unsigned int size)
{
    DEBUG("%s ", str);
    for (unsigned i = 0; i < size; ++i) {
        DEBUG("%02X ", (unsigned)buf[i]);
    }
    DEBUG("\n\n");
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

    //char *common_name = strndup(CONFIG_WOT_CL_COMMON_NAME, strlen(CONFIG_WOT_CL_COMMON_NAME));
    /*compressing pubkey*/
    const struct uECC_Curve_t *curve = uECC_secp256r1();
    uECC_compress(credentials_module.public_key, pubkey_comp, curve);
    //uECC_compress(ecdsa_pub_key_client, pubkey_comp, curve);
    /*encode common name*/
    //cbor_encode_text_stringz(&array_encoder, common_name );
    cbor_encode_text_stringz(&array_encoder, CONFIG_WOT_CL_COMMON_NAME );
    /*encode public key*/
    cbor_encode_byte_string(&array_encoder, pubkey_comp, PUB_KEY_COMPRESS_SIZE);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, cbor_buf_csr);

    print_hex("c509 client csr : ", cbor_buf_csr, (unsigned int)cbor_len);

    return cbor_len;
}
#endif /*CONFIG_WOT_CL_COMMON_NAME*/

#if CONFIG_WOT_USE_CRYPTO_CELL
int _set_crypto_cell_private_key(CRYS_ECPKI_UserPrivKey_t *crypto_pvt_key)
{
    int ret = 0;
    CRYS_ECPKI_Domain_t *pDomain = (CRYS_ECPKI_Domain_t *)CRYS_ECPKI_GetEcDomain(
        CRYS_ECPKI_DomainID_secp256r1);
    ret = CRYS_ECPKI_BuildPrivKey(pDomain, credentials_module.private_key, (uint32_t)PVT_KEY_SIZE, crypto_pvt_key);
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
 * @brief function create signature of client certficate,self signed using clients private key
 *
 * @param cbor_buf_csr
 * @param csr_len
 * @param signature
 * @return int
 */
static int _wot_create_signature_client(uint8_t *cbor_buf_csr, int csr_len, uint8_t *signature)
{
    
    #if CONFIG_WOT_USE_CRYPTO_CELL
    int ret = 0;
    CRYS_ECDSA_SignUserContext_t SignUserContext;
    SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc = CRYS_RND_GenerateVector;
    CRYS_ECPKI_UserPrivKey_t UserPrivKey;
    CRYS_ECDH_TempData_t signOutBuff;
    uint32_t ecdsa_sig_size = ECC_SIGN_LEN;
    _set_crypto_cell_private_key(&UserPrivKey);    
    cryptocell_enable();
    
    ret = CRYS_ECDSA_Sign(rndState_ptr, rndGenerateVectFunc,
                          &SignUserContext, &UserPrivKey, CRYS_ECPKI_HASH_SHA256_mode , cbor_buf_csr,
                          (uint32_t)csr_len, (uint8_t*)&signOutBuff, &ecdsa_sig_size);    
    cryptocell_disable();
        if (ret != SA_SILIB_RET_OK){
        DEBUG("CRYS_ECDSA_Sign failed with 0x%x \n",ret);
        return 1;
    }
    else
    {
        DEBUG("CRYS_ECDSA_Sign success\n");
        memcpy(signature,(uint8_t*)&signOutBuff,ECC_SIGN_LEN);
        return 0;
    }
    
    #else
    /*hashing+signature*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };

    sha256((uint8_t *)cbor_buf_csr, csr_len, hash_cert);
    print_hex("hash of client csr : ", hash_cert, (unsigned int)SHA256_DIGEST_LENGTH);

    const struct uECC_Curve_t *curve = uECC_secp256r1();

    /*if ((uECC_sign(ecdsa_priv_key_client, hash_cert, sizeof(hash_cert), signature, curve)) != 1) {
        printf("\nfailed to sign with private key\n");
       }*/
    if ((uECC_sign(credentials_module.private_key, hash_cert, sizeof(hash_cert), signature,
                   curve)) != 1) {
        DEBUG("\nfailed to sign with private key\n");
    }
    #endif
    print_hex("selfsign client hash : ", signature, ECC_SIGN_LEN);
    return 0;

}


int wot_get_cbor_certificate_client(uint8_t *buf)
{

    uint8_t cbor_len = 0;
    uint8_t cbor_len_csr = 0;
    uint8_t *cbor_buf_csr = (uint8_t *)calloc(64, sizeof(uint8_t));

    /*64 byte sign using selfsign*/
    uint8_t *signature = (uint8_t *)calloc(ECC_SIGN_LEN, sizeof(uint8_t));

    /*get cbor cert to be signed*/
    cbor_len_csr = _wot_get_cbor_certificate_csr(cbor_buf_csr, 64);

    /*self sign*/
    _wot_create_signature_client(cbor_buf_csr, cbor_len_csr, signature);

    CborEncoder encoder;
    CborEncoder array_encoder;

    cbor_encoder_init(&encoder, buf, CBOR_BUFSIZE, 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 2);

    cbor_encode_byte_string(&array_encoder, cbor_buf_csr, cbor_len_csr);
    cbor_encode_byte_string(&array_encoder, signature, ECC_SIGN_LEN);

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
static int _wot_check_rd_cbor_cert_valid(uint8_t *cbor_buf_csr, uint8_t cert_len,
                                         uint8_t *signature,
                                         uint8_t sig_len)
{

    /*decrypting signature to get hash of cert*/
    cipher_t cipher;
    uint8_t *sig_decrypt = (uint8_t *)calloc(PSK_SIGN_LEN, sizeof(uint8_t));

    if (cipher_init(&cipher, CIPHER_AES, credentials_module.psk_key, PSK_SIGN_LEN) < 0) {
        DEBUG("aes init failed!\n");
    }

    if (cipher_decrypt(&cipher, signature, sig_decrypt) < 0) {
        DEBUG("aes decryption failed!\n");
    }

    if (cipher_decrypt(&cipher, signature + 16, sig_decrypt + 16) < 0) {
        DEBUG("aes decryption failed!\n");
    }

    /*compute hash of certificate*/
    uint8_t hash_cert[SHA256_DIGEST_LENGTH] = { 0 };
    sha256((uint8_t *)cbor_buf_csr, cert_len, hash_cert);

    print_hex("decrypted signature : ", sig_decrypt, PSK_SIGN_LEN);
    print_hex("calculated hash : ", hash_cert, (unsigned int)sizeof(hash_cert));

    /*check if certificate is valid*/
    if (memcmp(sig_decrypt, hash_cert, PSK_SIGN_LEN) != 0) {
        DEBUG("invalid certificate\n");
        return 1;
    }
    else {
        DEBUG("valid certificate\n");
    }
    free(sig_decrypt);

    return 0;

}

/**
 * @brief function to parse and store cbor certificate in list
 *
 * @param payload
 * @param payload_len
 * @return CborError
 */
CborError _wot_store_cert(uint8_t *payload, uint16_t payload_len, uint16_t scene)
{
    CborParser parser;
    CborValue it;

    uint8_t *pub_buf = (uint8_t *)calloc(PUB_KEY_SIZE, sizeof(uint8_t));
    uint8_t *pub_buf_compress = (uint8_t *)calloc(PUB_KEY_COMPRESS_SIZE, sizeof(uint8_t));
    char *common_name = (char *)calloc(NAME_MAX_LEN, sizeof(char));
    size_t common_name_len = 0;

    CborError err = cbor_parser_init(payload, payload_len, 0, &parser, &it);

    if (err) {
        DEBUG("error parsing cbor certificate....\n");
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

            print_hex("public key : ", pub_buf, (unsigned int)PUB_KEY_SIZE);

        }
    }
    //wot_cert_t *node = wot_cert_add(common_name, (int)common_name_len, pub_buf);
    /*scene 0=>registration,scene 1=>lookup*/
    if (scene == 0) {
        wot_cert_t *node = wot_cert_add(common_name, strlen(common_name), pub_buf);
        DEBUG("stored node name:%s\n", node->name);
        DEBUG("stored  %s cert in list\n", node->name);
    }
    else if (scene == 1) {

        #if CONFIG_WOT_STORE_LOOKUP_CERT
        /*if application wants to store the lookup certificates in list*/
        wot_cert_t *node = wot_cert_add(common_name, strlen(common_name), pub_buf);
        if (node != NULL) {
            DEBUG("stored  %s cert in list\n", node->name);
        }
        #else
        /*if application does not wants to store the lookup certificates in list*/
        DEBUG("not storing cert  in list\n");
        wot_cert_t *node = (wot_cert_t *)calloc(1, sizeof(wot_cert_t));
        if (node != NULL) {
            memcpy(&node->name, common_name, strlen(common_name));
            memcpy(&node->pubkey, pub_buf, PUB_KEY_SIZE);
            DEBUG("node name:%s\n", node->name);
        }
        #endif
        c509_end_time = xtimer_now_usec();
        lookup_callback(0, node);
    }


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
            DEBUG("cbor rd cert len:%d\n", cert_len);
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
            DEBUG("signature len:%d\n", sig_len);
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

        int ret = _wot_check_rd_cbor_cert_valid(cbor_buf_csr, cert_len, signature, sig_len);

        if (ret != 0) {
            DEBUG("invalid certificate\n");
            return 1;
        }
        else {
            DEBUG("valid certificate\n");
            _wot_store_cert(cbor_buf_csr, cert_len, 0);

        }
        free(cbor_buf_csr);
        free(signature);
    }
    return 0;

}


/*---------------------loookup---------------------------*/




#if CONFIG_WOT_USE_CRYPTO_CELL
int _set_crypto_cell_public_key(CRYS_ECPKI_UserPublKey_t *crypto_pub_key, wot_cert_t *node)
{
    //uint8_t pub_key[65];
    uint8_t *pub_key = (uint8_t *)calloc(CRYPTO_CELL_PUB_KEY_SIZE, sizeof(uint8_t));
    
    pub_key[0] = 0x04; //Uncompressed pub key pc/x/y
    memcpy(pub_key + 1, node->pubkey, PUB_KEY_SIZE);
    CRYS_ECPKI_Domain_t *pDomain = (CRYS_ECPKI_Domain_t *)CRYS_ECPKI_GetEcDomain(
        CRYS_ECPKI_DomainID_secp256r1);
    CRYS_ECPKI_BUILD_TempData_t pTempBuff;
    
    int ret = _DX_ECPKI_BuildPublKey(pDomain, pub_key, (uint32_t)CRYPTO_CELL_PUB_KEY_SIZE, 0, crypto_pub_key, &pTempBuff);
    if (ret != CRYS_OK) {
        DEBUG("failed to copy crypto pub key");
        free(pub_key);
        return 1;
    }
    else {
        DEBUG("copied crypto pub key\n");
        free(pub_key);
    }
    return 0;

}
#endif


uint32_t crypto_start_time;
uint32_t crypto_end_time;
/**
 * @brief function to check if the received client certificate during lookup is valid
 *
 * @param cbor_buf_csr
 * @param cert_len
 * @param signature
 * @param sig_len
 * @param rd_common_name
 * @return int
 */
static int _wot_check_lookup_cbor_cert_valid(uint8_t *cbor_buf_csr, uint8_t cert_len,
                                             uint8_t *signature,
                                             uint8_t sig_len, char *rd_common_name)
{
    wot_cert_t *node = wot_cert_get(rd_common_name);

    if (node == NULL) {
        DEBUG("public key not found for %s\n", rd_common_name);
        return 1;
    }
    #if CONFIG_WOT_USE_CRYPTO_CELL
    int ret = 0;
    CRYS_ECDSA_VerifyUserContext_t VerifyUserContext;
    CRYS_ECPKI_UserPublKey_t UserPublKey;
    _set_crypto_cell_public_key(&UserPublKey, node);

    crypto_start_time = xtimer_now_usec();
    cryptocell_enable();
    ret =  CRYS_ECDSA_Verify(&VerifyUserContext, &UserPublKey, CRYS_ECPKI_HASH_SHA256_mode,
                             signature, ECC_SIGN_LEN, cbor_buf_csr, cert_len);
    cryptocell_disable();
    crypto_end_time = xtimer_now_usec();
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
    crypto_start_time = xtimer_now_usec();
    if ((uECC_verify(node->pubkey, hash_cert, sizeof(hash_cert), signature, curve)) != 1) {
        DEBUG("invalid certificate\n");
        return 1;
    }
    else {
        DEBUG("verified with public key,valid certificate\n");
    }
    crypto_end_time = xtimer_now_usec();
    #endif
    //printf("uecc time:%ld,\n", (uecc_end_time - uecc_start_time));
    return 0;
}



/**
 * @brief function to parse lookup request response
 *
 * @param payload
 * @param payload_len
 * @return CborError
 */
CborError wot_parse_cbor_cert_lookup(uint8_t *payload, uint16_t payload_len)
{
    /*the tme stamps are just for evaluation,needs to be removed*/


    c509_start_time = xtimer_now_usec();

    CborParser parser;
    CborValue it;
    size_t cert_len = 0;
    size_t sig_len = 0;
    uint8_t *cbor_buf_csr = NULL;
    uint8_t *signature = NULL;
    char *rd_common_name = (char *)calloc(NAME_MAX_LEN, sizeof(char));
    size_t rd_common_name_len = 0;

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


        /*get rd's name*/
        type = cbor_value_get_type(&recursed);
        if (type == CborTextStringType) {
            cbor_value_get_string_length(&recursed, &rd_common_name_len);
            err = cbor_value_copy_text_string(&recursed, rd_common_name, &rd_common_name_len,
                                              &recursed);
            if (err) {
                return err;
            }
            DEBUG("rd common name : %s\n", rd_common_name);
        }


        /*get certificate*/
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            cbor_value_get_string_length(&recursed, &cert_len);
            DEBUG("cbor rd cert len:%d\n", cert_len);
            cbor_buf_csr = (uint8_t *)calloc(cert_len, sizeof(uint8_t));
            err = cbor_value_copy_byte_string(&recursed, cbor_buf_csr, &cert_len,
                                              &recursed);
            if (err) {
                DEBUG("failed to copy certificate....\n");
                return err;
            }
        }

        /*get signature*/
        type = cbor_value_get_type(&recursed);
        if (type == CborByteStringType) {
            cbor_value_get_string_length(&recursed, &sig_len);
            DEBUG("signature len:%d\n", sig_len);
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

        int ret = _wot_check_lookup_cbor_cert_valid(cbor_buf_csr, cert_len, signature, sig_len,
                                                    rd_common_name);

        if (ret != 0) {
            DEBUG("invalid certificate\n");
            return 1;
        }
        else {
            DEBUG("valid certificate\n");
            _wot_store_cert(cbor_buf_csr, cert_len, 1);
            //c509_end_time = xtimer_now_usec();
            //printf("c509 processing time:%ld,\n", (c509_end_time - c509_start_time));

        }
        free(rd_common_name);
        free(cbor_buf_csr);
        free(signature);
    }
    return 0;

}

int wot_get_lookup_payload(uint8_t *buf, char *lookup_name)
{
    CborEncoder encoder, mapEncoder;

    cbor_encoder_init(&encoder, buf, 32, 0);
    cbor_encoder_create_map(&encoder, &mapEncoder, 2);
    cbor_encode_text_stringz(&mapEncoder, "client");
    cbor_encode_text_stringz(&mapEncoder, CONFIG_WOT_CL_COMMON_NAME);
    cbor_encode_text_stringz(&mapEncoder, "id");
    cbor_encode_text_stringz(&mapEncoder, lookup_name);
    cbor_encoder_close_container(&encoder, &mapEncoder);
    uint8_t cbor_len = cbor_encoder_get_buffer_size(&encoder, buf);
    //print_hex("cbor_encoded payload:", buf, (unsigned int)cbor_len);
    DEBUG("buf len:%d\n", cbor_len);
    return cbor_len;
}
