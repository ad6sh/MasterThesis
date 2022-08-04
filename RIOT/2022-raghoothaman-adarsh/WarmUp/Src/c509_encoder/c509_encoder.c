/**
 * @file cbor_encoder.c
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief 
 * @version 0.1
 * @date 2022-01-14
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include "cbor.h"
#include "c509_encoder.h"
#define ENABLE_DEBUG (0)
#include "debug.h"


int x509_to_cbor(x509_cert_t *cert_to_cbor)
{
    uint8_t buf[CBOR_BUFSIZE];
    uint8_t cbor_len = 0;
    CborEncoder encoder;
    CborEncoder array_encoder;

    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    cbor_encoder_create_array(&encoder, &array_encoder, 8);
    /*version*/
    cbor_encode_int(&array_encoder, cert_to_cbor->version);
    /*Serial Number*/
    cbor_encode_byte_string(&array_encoder, cert_to_cbor->serial_num,
                            cert_to_cbor->serial_num_size);
    /*Issuer*/
    cbor_encode_text_stringz(&array_encoder, cert_to_cbor->issuer_cn );
    /*Validity*/
    cbor_encode_uint(&array_encoder, cert_to_cbor->not_before);
    cbor_encode_uint(&array_encoder, cert_to_cbor->not_after);
    /*Subject*/
    cbor_encode_text_stringz(&array_encoder, cert_to_cbor->subject_cn);
    /*Public-Key*/
    cbor_encode_byte_string(&array_encoder, cert_to_cbor->public_key, cert_to_cbor->pub_key_size);
    /*Signature*/
    cbor_encode_byte_string(&array_encoder, cert_to_cbor->sig_compressed, SIG_COMPRESS_LEN);

    cbor_encoder_close_container(&encoder, &array_encoder);
    cbor_len = cbor_encoder_get_buffer_size(&encoder, buf);
    DEBUG("cbor buffer size:%d\n", cbor_len);
    printf("c509 cert:");
    for (int i = 0; i < cbor_len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
    return 0;

}
