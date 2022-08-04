#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <stdlib.h>
#include "x509_cert.h"


int display_extrafields(DecodedCert *decoded_cert);
int get_unix_time_stamp(char *time_str, time_t *time);


x509_cert_t cert_to_en;

int x509_parse(int argc, char **argv)
{

    if (argc != 2)
    {
        printf("usage: %s cert_name.pem\n", argv[0]);
        return 1;
    }

    char *file_name;
    file_name = strdup(argv[1]);

    FILE *file;
    int der_cert_size;
    int pem_cert_size;
    byte der_cert_buf[4096];
    byte pem_cert_buf[4096];
    char not_before_str[20];
    char not_after_str[20];
    DecodedCert decoded_cert;

    //wolfSSL_Init();
    //wolfCrypt_Init();

    /* open and read pem-formatted cert into buffer */
    file = fopen(file_name, "rb");
    if (!file)
    {
        printf("can't open certificate\n");
        return 1;
    }

    pem_cert_size = fread(pem_cert_buf, 1, sizeof(pem_cert_buf), file);
    fclose(file);

    if (pem_cert_size <= 0)
    {
        printf("pem cert read error:%d\n", (int)pem_cert_size);
        return 1;
    }

    der_cert_size = wc_CertPemToDer(pem_cert_buf, pem_cert_size, der_cert_buf, sizeof(der_cert_buf), CERT_TYPE);

    if (der_cert_size <= 0)
    {
        printf("cant convert pem to der:%d\n", (int)der_cert_size);
        return 1;
    }

    InitDecodedCert(&decoded_cert, der_cert_buf, (word32)der_cert_size, 0);

    ParseCert(&decoded_cert, CERT_TYPE, NO_VERIFY, NULL);

    int i;

    /*--------------version----------------*/
    printf("\n\nversion: %d\n\n", decoded_cert.version);
    cert_to_en.version = decoded_cert.version; //X.509 specification: An integer 0–2 specifying the version of the certificate.
     /*--------------version end----------------*/
    
    /*--------------serial number----------------*/
    printf("serial number: ");
    for (i = 0; i < (int)decoded_cert.serialSz; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", decoded_cert.serial[i]);
        cert_to_en.serial_num[i] = decoded_cert.serial[i];
    }
    //memcpy(&(cert_to_en.serial_num), &(decoded_cert.serial), decoded_cert.serialSz);
    cert_to_en.serial_num_size=decoded_cert.serialSz;
    printf("\n\n");
    /*--------------serial number end ----------------*/
    
    /*--------------issuer----------------*/
    char *issuer_cn_pos;
    printf("issuer: %s\n", decoded_cert.issuer); //TODO ONLY CN ? DONE
    issuer_cn_pos = strstr(decoded_cert.issuer, "CN=");
    if (issuer_cn_pos)
    {
        //printf("issuer CN found %s \n",issuer_cn_pos);
        char *issuer_cn = strtok(issuer_cn_pos, "/");
        //printf("%s\n", issuer_cn+3);
        cert_to_en.issuer_cn = strdup(issuer_cn + 3);
        //printf("%s\n", cert_to_en.issuer_cn);
    }
    else
    {
        cert_to_en.issuer_cn = "not available";
    }
    printf("issuerCN:%s\n\n", cert_to_en.issuer_cn);
    /*--------------issuer end----------------*/

    /*--------------validity----------------*/
    //printf("not before: %.*s\n\n", decoded_cert.beforeDateLen, decoded_cert.beforeDate);
    sprintf(not_before_str, "%.*s", decoded_cert.beforeDateLen, decoded_cert.beforeDate);
    printf("not before: %s\n", not_before_str);
    get_unix_time_stamp(not_before_str, &(cert_to_en.not_before));
    printf("not before time stamp: %ld\n\n", (long)cert_to_en.not_before);

    //printf("not after: %.*s\n\n", decoded_cert.afterDateLen, decoded_cert.afterDate);
    sprintf(not_after_str, "%.*s", decoded_cert.afterDateLen, decoded_cert.afterDate);
    printf("not after::%s\n", not_after_str);
    get_unix_time_stamp(not_after_str, &(cert_to_en.not_after));
    printf("not after time stamp: %ld\n\n", (long)cert_to_en.not_after);
    /*--------------validity end ----------------*/


    /*--------------subject ----------------*/
    char *subject_cn_pos;
    printf("subject: %s\n", decoded_cert.subject); //TODO
    subject_cn_pos = strstr(decoded_cert.subject, "CN=");
    if (subject_cn_pos)
    {
        cert_to_en.subject_cn = strdup(decoded_cert.subjectCN);
    }
    else
    {
        cert_to_en.subject_cn = "not available";
    }
    printf("subjectCN:%s\n\n", cert_to_en.subject_cn);
    /*--------------subject end----------------*/


    /*--------------public key ----------------*/
    printf("public key: ");
    for (i = (PUBKEY_OFFSET); i < (int)decoded_cert.pubKeySize; i++)
    {
        if (i > PUBKEY_OFFSET)
            printf(":");
        printf("%02X", decoded_cert.publicKey[i]);
        cert_to_en.public_key[i] = decoded_cert.publicKey[i];
    }
    //memcpy(&(cert_to_en.public_key), (decoded_cert.publicKey) + PUBKEY_OFFSET, (decoded_cert.pubKeySize - PUBKEY_OFFSET));
    cert_to_en.pub_key_size = (decoded_cert.pubKeySize - PUBKEY_OFFSET);
    printf("\n\n");

    /*printf("public key: ");
    for (i = 0; i < cert_to_en.pub_key_size; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", cert_to_en.public_key[i]);
    }
    printf("\n\n");*/
    /*--------------public key end----------------*/

    /*--------------signature ----------------*/
    printf("signature: ");
    for (i = 0; i < (int)decoded_cert.sigLength; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", decoded_cert.signature[i]);
        cert_to_en.signature[i] = decoded_cert.signature[i];
    }
    printf("\n\n");

    //memcpy(&(cert_to_en.signature), &(decoded_cert.signature), decoded_cert.sigLength);
    cert_to_en.signature_size = decoded_cert.sigLength;

    /*printf("length of signature:%d\n", decoded_cert.sigLength);
    printf("length of signature in struct :%d\n", cert_to_en.signature_size);
    printf("length of signature in struct :%d\n", sizeof(cert_to_en.signature));
    printf("\n\n");

    printf("signature: ");
    for (i = 0; i < cert_to_en.signature_size; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", cert_to_en.signature[i]);
    }
    printf("\n\n");*/
    /*--------------signature end----------------*/


    //display_extrafields(&decoded_cert);
    FreeDecodedCert(&decoded_cert);
    x509_to_cbor(&cert_to_en);

    //wolfCrypt_Cleanup();
    //wolfSSL_Cleanup();
    return 0;
}

int get_unix_time_stamp(char *time_str, time_t *time)
{
    struct tm t;
    if (strlen(time_str) > 15)
    {
        t.tm_year = (atoi(strndup(time_str + 2, 4)) - 1900); //YYYY:MM:DD
        t.tm_mon = (atoi(strndup(time_str + 6, 2)) - 1);
        t.tm_mday = (atoi(strndup(time_str + 8, 2)));
        t.tm_hour = (atoi(strndup(time_str + 10, 2)));
        t.tm_min = (atoi(strndup(time_str + 12, 2)));
        t.tm_sec = (atoi(strndup(time_str + 14, 2)));
        t.tm_isdst = -1;
    }
    else
    {
        t.tm_year = (atoi(strndup(time_str + 2, 2)));
        t.tm_year = (t.tm_year >= 50) ? (t.tm_year + 1900) : (t.tm_year + 2000); //x509 YY::MM:DD
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

int display_extrafields(DecodedCert *decoded_cert)
{
    /*printf("subject CN:%s\n", decoded_cert->subjectCN);
    printf("length of signature:%d\n", decoded_cert->sigLength);
    printf("serial number size:%d\n", decoded_cert->serialSz);
    printf("before date length:%d\n", decoded_cert->beforeDateLen);
    printf("after date length:%d\n", decoded_cert->afterDateLen);
    printf("decoded_cert.pubKeySize %d\n", decoded_cert->pubKeySize);
    printf("offset to start of cert:%d\n", (word32)decoded_cert->certBegin);
    printf("offset to start of signature:%d\n", decoded_cert->sigIndex);
    printf("public key stored:%d\n", decoded_cert->pubKeyStored);
    printf("signatureOID:%d\n", decoded_cert->signatureOID);
    printf("keyOID:%d\n", decoded_cert->keyOID);
    printf("srcIdx:%d\n", decoded_cert->srcIdx);
    printf("maxIdx:%d\n", decoded_cert->maxIdx);*/
    //int i;
    //char not_after_str[16];
    char not_before_str[20];

    sprintf(not_before_str, "%.*s", decoded_cert->beforeDateLen, decoded_cert->beforeDate);
    printf("not before: %.*s \n", decoded_cert->beforeDateLen, decoded_cert->beforeDate);
    printf("not_before_str:%s\n", not_before_str);
    printf("not_before_str len:%d\n", strlen(not_before_str));

    //This happens when the length is greater than 15,else 2 bytes less and convert year
    struct tm t;
    time_t t_of_day;
    t.tm_year = (atoi(strndup(not_before_str + 2, 4)) - 1900);
    t.tm_mon = (atoi(strndup(not_before_str + 6, 2)) - 1);
    t.tm_mday = (atoi(strndup(not_before_str + 8, 2)));
    t.tm_hour = (atoi(strndup(not_before_str + 10, 2)));
    t.tm_min = (atoi(strndup(not_before_str + 12, 2)));
    t.tm_sec = (atoi(strndup(not_before_str + 14, 2)));
    t.tm_isdst = -1; // Is DST on? 1 = yes, 0 = no, -1 = unknown
    t_of_day = timegm(&t);

    printf("seconds since the Epoch: %ld\n", (long)t_of_day);

    /*for (i = 0; i < (int)decoded_cert->beforeDateLen; i++)
    {
        //if (i > 0) printf(":");
        printf("%02X", decoded_cert->beforeDate[i]);
    }*/
    printf("\n\n");

    printf("not after: %.*s \n", decoded_cert->afterDateLen, decoded_cert->afterDate);
    /*for (i = 0; i < (int)decoded_cert->afterDateLen; i++)
    {
        //if (i > 0) printf(":");
        printf("%02X", decoded_cert->afterDate[i]);
    }
    printf("\n\n");*/

    return 0;
}