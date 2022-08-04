/**
 * @file x509_cert.h
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-01-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef X_509_CERT_H
#define X_509_CERT_H

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SERIAL_NUM_MAX_LEN 20
#define PUB_KEY_MAX_LEN 65 //32 byte x,32 byte y and one byte to show compressed/decompressed
#define SIG_MAX_LEN 75
#define SIG_COMPRESS_LEN 64 //32 byte r,32 byte s

typedef struct {
    uint8_t version;
    uint8_t serial_num_size;
    uint8_t serial_num[SERIAL_NUM_MAX_LEN];
    char *issuer_cn;
    time_t not_before;
    time_t not_after;
    char *subject_cn;
    uint8_t pub_key_size;
    uint8_t public_key[PUB_KEY_MAX_LEN];
    uint8_t signature_size;
    uint8_t signature[SIG_MAX_LEN];
    uint8_t sig_compressed[SIG_COMPRESS_LEN];
} x509_cert_t;

#ifdef __cplusplus
}
#endif

#endif /* X_509_CERT_H */
