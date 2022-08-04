/*
 * Copyright (C) 2018 Freie Universität Berlin
 * Copyright (C) 2018 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Tests tinycbor package
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 *
 * @}
 */

#include <string.h>

#include "embUnit.h"
#include "embUnit/embUnit.h"
#include "fmt.h"
#include "cbor.h"

#define BUFSIZE 256

int extract_int(const uint8_t *buffer, size_t len)
{
    CborParser parser;
    CborValue value;
    int result;
    if (cbor_parser_init(buffer, len, 0, &parser, &value) != CborNoError)
        return 0;
    if (!cbor_value_is_integer(&value) ||
        cbor_value_get_int(&value, &result) != CborNoError)
        return 0;
    return result;
}

int main(void)
{

    /*CborEncoder encoder;
uint8_t  buffer[BUFSIZE];    
//const char *string= "RFC test CA" ;
cbor_encoder_init(&encoder,buffer,sizeof(buffer),0);

cbor_encode_text_stringz(&encoder,"RFC test CA");
printf("%s",buffer);*/

    uint8_t buf[100];
    uint8_t cbor_len = 0;
    CborEncoder encoder;
    CborEncoder array_encoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    //cbor_encode_int(&encoder, 125);
    //cbor_encode_text_stringz(&encoder, "RFC test CA");
    cbor_encoder_create_array(&encoder,&array_encoder,3);
    cbor_encode_int(&array_encoder, 3);
    cbor_encode_uint(&array_encoder,128269);
    //cbor_encode_int(&array_encoder, 0); 
    cbor_encode_text_stringz(&array_encoder, "RFC test CA");
    cbor_encoder_close_container(&encoder, &array_encoder); 

    
    
    
    
    
    char *out = "";
    printf("buffer size:%d\n", cbor_encoder_get_buffer_size(&encoder, buf));
    cbor_len = fmt_bytes_hex(out, buf, cbor_encoder_get_buffer_size(&encoder, buf));
    out[cbor_len] = '\0';
    printf("CBOR :%s\n", out);

    /*int dec = extract_int(buf, sizeof(buf));
    printf("decoded :%d\n", dec);*/

    return 0;
}
