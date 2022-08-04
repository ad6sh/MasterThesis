/**
 * @file x509_parser.h
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-01-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef X_509_PARSER_H
#define X_509_PARSER_H

#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <time.h>
#include "x509_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PUBKEY_OFFSET 26
#define TIME_STRING_LEN 17
/**
 * @brief Get the unix time stamp object
 *
 * @param time_str
 * @param time
 * @return int
 */

static int get_unix_time_stamp(char *time_str, time_t *time);
/**
 * @brief Get the common name object
 *
 * @param input_string
 * @return char*
 */
static char *get_common_name(char *input_string);

/**
 * @brief get integers r,s from signature
 *
 * @param cert_in
 * @return int
 */
static int compress_signature(x509_cert_t *cert_in);

#ifdef __cplusplus
}
#endif

#endif /* X_509_PARSER_H */
