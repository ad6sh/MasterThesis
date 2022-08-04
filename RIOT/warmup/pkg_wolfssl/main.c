/*
 * Copyright (C) 2019 Kaleb J. Himes, Daniele Lacamera
 *
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       wolfSSL cryptographic library test
 *
 * @author      Kaleb J. Himes <kaleb@wolfssl.com>
 *              Daniele Lacamera <daniele@wolfssl.com>
 *
 * @}
 */

#include <stdio.h>
#include "xtimer.h"
#include "log.h"

//#include <wolfssl/options.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>


#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfcrypt/test/test.h>
#ifdef MODULE_WOLFCRYPT_BENCHMARK
#include <wolfcrypt/benchmark/benchmark.h>
#endif

//#include <wolfssl/options.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/openssl/x509v3.h>

//#include <wolfssl/certs_test.h>

#define WOLFSSL_WOLFSSL_TYPE_DEFINED

static void err_sys(const char *msg, int ret)
{
    if (ret)
    {
        printf("ERROR: %s, ret = %d\n", msg, ret);
    }
    else
    {
        printf("ERROR: %s\n", msg);
    }
    exit(EXIT_FAILURE);
}

static void check_ret(char *call, int ret)
{
    if (ret != 0)
    {
        printf("call: %s\n", call);
        printf("ret = %d\n", ret);
        exit(-99);
    }
    return;
}

int main(void)
{
    LOG_INFO("wolfSSL Crypto Test!\n");

    FILE *file;
    int derCertSz;
    int pemCertSz;
    byte derCert[4096];
    byte pemCert[4096];
    WOLFSSL_X509 *cert;

    DecodedCert decodedCert;
    //wolfSSL_Init();

    int ret;
   

     wolfCrypt_Init();

    /* open and read DER-formatted cert into buffer */
    /*file = fopen("wolftest.der", "rb");
    if (!file)
        err_sys("can't open client certificate", 0);
    
    derCertSz = fread(derCert, 1, sizeof(derCert), file);    
    fclose(file);

    printf("read bytes = %d\n\n", (int) derCertSz);
    if (derCertSz <= 0) {
        return -1;
    }*/

    //file = fopen("example-cert.pem", "rb");
    //file = fopen("wolftest.pem", "rb");
    file = fopen("testcert.pem", "rb");
    if (!file)
        err_sys("can't open client certificate", 0);

    pemCertSz = fread(pemCert, 1, sizeof(pemCert), file);
    fclose(file);

    if (pemCertSz <= 0)
    {
        printf("pem cert read error:%d\n", (int)pemCertSz);
        return -1;
    }

    derCertSz = wc_CertPemToDer(pemCert, pemCertSz, derCert, 4096, CERT_TYPE);

    printf("size of pem:%d\n\n", pemCertSz);
    printf("size of der:%d\n\n", derCertSz);

    cert = wolfSSL_X509_d2i(&cert, derCert, derCertSz);

    InitDecodedCert(&decodedCert, derCert, (word32)derCertSz, 0);

    ret = ParseCert(&decodedCert, CERT_TYPE, NO_VERIFY, NULL);
    check_ret("ParseCert", ret);

    //printf("decodedCert.pubKeySize %d\n\n", decodedCert.pubKeySize);
    //WOLFSSL_BUFFER(decodedCert.publicKey, decodedCert.pubKeySize);

    printf("offset to start of cert:%d\n\n", decodedCert.certBegin);
    printf("offset to start of signature:%d\n\n", decodedCert.sigIndex);
    printf("public key stored:%d\n\n", decodedCert.pubKeyStored);
    /*printf("signatureOID:%d\n\n",decodedCert.signatureOID);
    printf("keyOID:%d\n\n",decodedCert.keyOID);
    printf("srcIdx:%d\n\n",decodedCert.srcIdx);
    printf("maxIdx:%d\n\n",decodedCert.maxIdx);*/

    printf("version:%d\n\n", decodedCert.version);
    printf("subject CN:%s\n\n", decodedCert.subjectCN);
    printf("issuer:%s\n\n", decodedCert.issuer);
    printf("subject:%s\n\n", decodedCert.subject);
    printf("length of signature:%d\n\n", decodedCert.sigLength);
    printf("serial number size:%d\n\n", decodedCert.serialSz);
    printf("before date length:%d\n\n", decodedCert.beforeDateLen);
    printf("after date length:%d\n\n", decodedCert.afterDateLen);

    int i;
    printf("not before: %.*s ", decodedCert.beforeDateLen, decodedCert.beforeDate);

    /*for (i = 0; i < (int)decodedCert.beforeDateLen; i++)
    {
        //if (i > 0) printf(":");
        printf("%02X", decodedCert.beforeDate[i]);
    }*/
    printf("\n\n");

    printf("not after: %.*s ", decodedCert.afterDateLen, decodedCert.afterDate);
    /*for (i = 0; i < (int)decodedCert.afterDateLen; i++)
    {
        //if (i > 0) printf(":");
        printf("%02X", decodedCert.afterDate[i]);
    }*/
    printf("\n\n");

    printf("serial number:");
    for (i = 0; i < (int)decodedCert.serialSz; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", decodedCert.serial[i]);
    }
    printf("\n\n");

    printf("public key");
    for (i = (decodedCert.certBegin + 22); i < (int)decodedCert.pubKeySize; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", decodedCert.publicKey[i]);
    }
    printf("\n\n");

    printf("signature:");
    for (i = 0; i < (int)decodedCert.sigLength; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", decodedCert.signature[i]);
    }
    printf("\n\n");

    FreeDecodedCert(&decodedCert);

    wolfCrypt_Cleanup();

    printf("Success\n");

    return 0;
}
