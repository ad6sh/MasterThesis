/**
 * @file cbor_encoder.h
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief
 * @version 0.1
 * @date 2022-01-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifndef C509_ENCODER_H
#define C509_ENCODER_H

#include "x509_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CBOR_BUFSIZE 256

/**
 * @brief function for converting internal x509 cert structure to cbor
 *
 * @param cert_to_cbor
 * @return int
 */
int x509_to_cbor(x509_cert_t *cert_to_cbor);

#ifdef __cplusplus
}
#endif

#endif /* C509_ENCODER_H */
