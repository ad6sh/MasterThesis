#include <stdio.h>
#include "cbor.h"
#include "fmt.h"
#include <string.h>

#define BUFSIZE 256
#include "x509_cert.h"


uint8_t publicKey[] = {0x04, 0x8e, 0xdc,0xb9,0x92,0x59,0x51,0x40,0x2e,0x3f,0x33,0x44,0x55,0x70,0x80,0x16,0xbc,0x41,0x84,0xab,0x47,0x3e,0x8b,0x93,0x6a,0xa0,0x16,0x78,0x0a,0xe9,0x49,0x9a,0xd5,0xfe,0x08,0xcc,0xc3,0x23,0x2f,0x26,0x5a,0x14,0xcc,0xb1,0x8e };

int cbor_encoder(int argc, char **argv)
{
    (void)argc;
    (void)argv;


    /*for (int i = 0 ;i < (int)sizeof(publicKey); i++)
    {
        if (i > 0)
            printf(":");
        printf("%02X", publicKey[i]);
    }

    printf("\n");*/
    
    
    
    uint8_t buf[BUFSIZE];
    uint8_t cbor_len = 0;
    CborEncoder encoder;
    CborEncoder array_encoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    cbor_encoder_create_array(&encoder,&array_encoder,8);
    
    //version
    cbor_encode_int(&array_encoder, 3);

    //Serial Number
    cbor_encode_uint(&array_encoder,128269);

    //Issuer
    cbor_encode_text_stringz(&array_encoder, "www.wolfssl.com");

    //Validity
    cbor_encode_uint(&array_encoder,1588792487);
    cbor_encode_uint(&array_encoder,1632078887);

    //Subject
    cbor_encode_text_stringz(&array_encoder, "www.yourDomain.com");


    //Public-Key
    cbor_encode_byte_string(&array_encoder,publicKey,sizeof(publicKey)); 		


    //Signature
    cbor_encode_byte_string(&array_encoder,publicKey,sizeof(publicKey)); 	

    cbor_encoder_close_container(&encoder, &array_encoder);

    
    
    cbor_len = cbor_encoder_get_buffer_size(&encoder,buf);

    printf("cbor buffer size:%d\n",cbor_len);


     for (int i = 0 ;i < cbor_len; i++)
    {
     
        printf("%02X", buf[i]);
    }

    printf("\n");
    /*char *out = "";
    printf("buffer size:%d\n", cbor_encoder_get_buffer_size(&encoder, buf));
    cbor_len = fmt_bytes_hex(out, buf, cbor_encoder_get_buffer_size(&encoder, buf));
    out[cbor_len] = '\0';
    printf("CBOR :%s\n", out);*/

    return 0;

}


int x509_to_cbor(x509_cert_t *cert_to_cbor)
{
  

    
    
    uint8_t buf[BUFSIZE];
    uint8_t cbor_len = 0;
    CborEncoder encoder;
    CborEncoder array_encoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);
    cbor_encoder_create_array(&encoder,&array_encoder,8);
    
    //version
    cbor_encode_int(&array_encoder, cert_to_cbor->version);

    //Serial Number TODO decide on uint or byte rray ?? some certificates have looong  serial number
    //as per IETF unsigned bignum (~biguint)...
    //cbor_encode_uint(&array_encoder,128269);
    cbor_encode_byte_string(&array_encoder,cert_to_cbor->serial_num,cert_to_cbor->serial_num_size); 	


    //Issuer
    cbor_encode_text_stringz(&array_encoder,cert_to_cbor->issuer_cn );

    //Validity
    cbor_encode_uint(&array_encoder,cert_to_cbor->not_before);
    cbor_encode_uint(&array_encoder,cert_to_cbor->not_after);

    //Subject
    cbor_encode_text_stringz(&array_encoder, cert_to_cbor->subject_cn);


    //Public-Key
    cbor_encode_byte_string(&array_encoder,cert_to_cbor->public_key,cert_to_cbor->pub_key_size); 		


    //Signature
    cbor_encode_byte_string(&array_encoder,cert_to_cbor->signature,cert_to_cbor->signature_size); 	

    cbor_encoder_close_container(&encoder, &array_encoder);

    
    
    cbor_len = cbor_encoder_get_buffer_size(&encoder,buf);

    printf("cbor buffer size:%d\n",cbor_len);


     for (int i = 0 ;i < cbor_len; i++)
    {
     
        printf("%02X", buf[i]);
    }

    printf("\n");
    /*char *out = "";
    printf("buffer size:%d\n", cbor_encoder_get_buffer_size(&encoder, buf));
    cbor_len = fmt_bytes_hex(out, buf, cbor_encoder_get_buffer_size(&encoder, buf));
    out[cbor_len] = '\0';
    printf("CBOR :%s\n", out);*/

    return 0;

}


