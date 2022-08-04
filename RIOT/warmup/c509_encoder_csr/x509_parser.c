/**
 * @file x509_parser.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-01-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "x509_parser.h"
#include "c509_encoder.h"
#define ENABLE_DEBUG (1)
#include "debug.h"



/* Check if the internal asn API's are available */
#if defined(WOLFSSL_TEST_CERT) || defined(OPENSSL_EXTRA) || \
    defined(OPENSSL_EXTRA_X509_SMALL)
    #define HAVE_DECODEDCERT
#endif

//#if defined(WOLFSSL_CERT_REQ) && defined(WOLFSSL_CERT_GEN) && \
//    defined(HAVE_ECC)

#define HEAP_HINT NULL
#define LARGE_TEMP_SZ 4096


int cbor_encoder(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s cert_name.pem\n", argv[0]);
        return 1;
    }
    char *file_name;
    int i;
    file_name = strdup(argv[1]);
    FILE *file;
    int der_cert_size = 0;
    int pem_cert_size = 0;
    byte *der_cert_buf = NULL;
    byte *pem_cert_buf = NULL;
    char not_before_str[20];
    char not_after_str[20];
    DecodedCert decoded_cert;
    x509_cert_t cert_to_en;

    der_cert_buf = (byte *)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (der_cert_buf == NULL) {
        goto exit;
    }
    XMEMSET(der_cert_buf, 0, LARGE_TEMP_SZ);

    pem_cert_buf = (byte *)XMALLOC(LARGE_TEMP_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem_cert_buf == NULL) {
        goto exit;
    }
    XMEMSET(pem_cert_buf, 0, LARGE_TEMP_SZ);

    wolfSSL_Debugging_ON();


    /* open and read pem-formatted cert into buffer */
    file = fopen(file_name, "rb");
    if (!file) {
        printf("can't open certificate\n");
        goto exit;;
    }

    pem_cert_size = fread(pem_cert_buf, 1, LARGE_TEMP_SZ, file);
    fclose(file);

    if (pem_cert_size <= 0) {
        printf("pem cert read error:%d\n", (int)pem_cert_size);
        goto exit;
    }
    DEBUG("\n\npem cert size:%d\n\n", pem_cert_size);

    der_cert_size = wc_CertPemToDer(pem_cert_buf, pem_cert_size, der_cert_buf,LARGE_TEMP_SZ,
                                    CERTREQ_TYPE);

    if (der_cert_size <= 0) {
        printf("cant convert pem to der:%d\n", (int)der_cert_size);
        goto exit;
    }

    DEBUG("\n\nder cert size:%d\n\n", der_cert_size);

    InitDecodedCert(&decoded_cert, der_cert_buf, der_cert_size, NULL);
    int ret = ParseCert(&decoded_cert, CERTREQ_TYPE, NO_VERIFY, NULL);

    DEBUG("ParseCert ret:%d\n", ret);
     if (ret != 0) {
        goto exit;
    }

    /*version-X.509 specification: An integer 0–2 specifying the version of the certificate.*/
    printf("version: %d\n\n", decoded_cert.version + 1);
    cert_to_en.version = (decoded_cert.version + 1);

    /*serial number*/
    printf("serial number: ");
    for (i = 0; i < (int)decoded_cert.serialSz; i++) {
        if (i > 0) {
            printf(":");
        }
        printf("%02X", decoded_cert.serial[i]);
        cert_to_en.serial_num[i] = decoded_cert.serial[i];
    }
    cert_to_en.serial_num_size = decoded_cert.serialSz;
    printf("\n\n");

    /*issuer*/
    printf("issuer: %s\n\n", decoded_cert.issuer);
    cert_to_en.issuer_cn = strdup(get_common_name(decoded_cert.issuer));
    DEBUG("issuerCN:%s\n\n", cert_to_en.issuer_cn);

    /*validity*/
    sprintf(not_before_str, "%.*s", decoded_cert.beforeDateLen, decoded_cert.beforeDate);
    printf("not before: %s\n\n", not_before_str);
    get_unix_time_stamp(not_before_str, &(cert_to_en.not_before));
    DEBUG("not before time stamp: %ld\n\n", (long)cert_to_en.not_before);

    sprintf(not_after_str, "%.*s", decoded_cert.afterDateLen, decoded_cert.afterDate);
    printf("not after: %s\n\n", not_after_str);
    get_unix_time_stamp(not_after_str, &(cert_to_en.not_after));
    DEBUG("not after time stamp: %ld\n\n", (long)cert_to_en.not_after);

    /*subject*/
    printf("subject: %s\n\n", decoded_cert.subject);
    cert_to_en.subject_cn = strdup(get_common_name(decoded_cert.subject));
    DEBUG("subjectCN:%s\n\n", cert_to_en.subject_cn);

    /*public key*/
    printf("public key: ");
    for (i = (PUBKEY_OFFSET); i < (int)decoded_cert.pubKeySize; i++) {
        if (i > PUBKEY_OFFSET) {
            printf(":");
        }
        printf("%02X", decoded_cert.publicKey[i]);
        cert_to_en.public_key[i - PUBKEY_OFFSET] = decoded_cert.publicKey[i];
    }
    cert_to_en.pub_key_size = (decoded_cert.pubKeySize - PUBKEY_OFFSET);
    printf("\n\n");

    /*signature*/
    printf("signature: ");
    for (i = 0; i < (int)decoded_cert.sigLength; i++) {
        if (i > 0) {
            printf(":");
        }
        printf("%02X", decoded_cert.signature[i]);
        cert_to_en.signature[i] = decoded_cert.signature[i];
    }
    printf("\n\n");
    cert_to_en.signature_size = decoded_cert.sigLength;
    /*get r and s from signature*/
    compress_signature(&cert_to_en);
    x509_to_cbor(&cert_to_en);

exit:

    XFREE(der_cert_buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pem_cert_buf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    FreeDecodedCert(&decoded_cert);
    return 0;
}

//#endif


static int  compress_signature(x509_cert_t *cert_in)
{
    /*30 LC 02 LR rep(r) 02 LS rep(s)*/
    switch (cert_in->signature[3]) {
    case 0x20:
        DEBUG("r valus is 32 bytes\n");
        memcpy(cert_in->sig_compressed, cert_in->signature + 4, 32);
        switch (cert_in->signature[37]) {
        case 0x20:
            DEBUG("s valus is 32 bytes\n");
            memcpy(cert_in->sig_compressed + 32, cert_in->signature + 38, 32);
            break;
        case 0x21:
            DEBUG("s valus is 33 bytes\n");
            memcpy(cert_in->sig_compressed + 32, cert_in->signature + 39, 32);
        default:
            break;
        }
        break;
    case 0x21:
        DEBUG("r valus is 33 bytes\n");
        memcpy(cert_in->sig_compressed, cert_in->signature + 5, 32);
        switch (cert_in->signature[38]) {
        case 0x20:
            DEBUG("s valus is 32 bytes\n");
            memcpy(cert_in->sig_compressed + 32, cert_in->signature + 39, 32);
            break;
        case 0x21:
            DEBUG("s valus is 33 bytes\n");
            memcpy(cert_in->sig_compressed + 32, cert_in->signature + 40, 32);
        default:
            break;
        }
        break;
    }
    DEBUG("sig: ");
    for (int i = 0; i < 64; i++) {
        if (i > 0) {
            DEBUG(":");
        }
        DEBUG("%02X", cert_in->sig_compressed[i]);
    }
    DEBUG("\n\n");
    return 0;
}



static int get_unix_time_stamp(char *time_str, time_t *time)
{
    struct tm t;

    /*x509 certs have time in YYYY:MM:DD:HH:MM:SS and YY:MM:DD:HH:MM:SS format*/
    if (strlen(time_str) == TIME_STRING_LEN) {
        t.tm_year = (atoi(strndup(time_str + 2, 4)) - 1900);
        t.tm_mon = (atoi(strndup(time_str + 6, 2)) - 1);
        t.tm_mday = (atoi(strndup(time_str + 8, 2)));
        t.tm_hour = (atoi(strndup(time_str + 10, 2)));
        t.tm_min = (atoi(strndup(time_str + 12, 2)));
        t.tm_sec = (atoi(strndup(time_str + 14, 2)));
        t.tm_isdst = -1;
    }
    else {
        t.tm_year = (atoi(strndup(time_str + 2, 2)));
        t.tm_year = (t.tm_year >= 50) ? (t.tm_year + 1900) : (t.tm_year + 2000);
        t.tm_year -= 1900;
        t.tm_mon = (atoi(strndup(time_str + 4, 2)) - 1);
        t.tm_mday = (atoi(strndup(time_str + 6, 2)));
        t.tm_hour = (atoi(strndup(time_str + 8, 2)));
        t.tm_min = (atoi(strndup(time_str + 10, 2)));
        t.tm_sec = (atoi(strndup(time_str + 12, 2)));
        t.tm_isdst = -1;
    }
    *time = timegm(&t);
    return 0;
}


static char *get_common_name(char *input_string)
{
    char *common_name;
    char *cn_pos;

    DEBUG("input string: %s\n", input_string);
    cn_pos = strstr(input_string, "CN=");
    if (cn_pos) {
        DEBUG("CN found %s \n", cn_pos);
        char *substring_cn = strtok(cn_pos, "/");
        common_name = strdup(substring_cn + 3);
    }
    else {
        common_name = "not available";
    }
    DEBUG("common_name: %s\n", common_name);
    return common_name;
}
