
#include <time.h>
#define PUBKEY_OFFSET 26
#define SERIAL_NUM_MAX_LEN 20
#define PUB_KEY_MAX_LEN 65 //32 byte x,32 byte y and one byte to show compressed/decompressed
#define PUB_KEY_COMPRESS_MAX_LEN 33
#define SIG_MAX_LEN 72
#define SIG_COMPRESS_MAX_LEN 64


typedef struct x509_cert
{
    int version;
    int serial_num_size;
    unsigned char serial_num[SERIAL_NUM_MAX_LEN]; //Or should be an integer ?
    char *issuer_cn;
    time_t not_before;
    time_t not_after;
    char *subject_cn;
    int pub_key_size;
    unsigned char public_key[PUB_KEY_MAX_LEN];
    unsigned char public_key_compressed[PUB_KEY_COMPRESS_MAX_LEN];
    int signature_size;
    unsigned char signature[SIG_MAX_LEN];
    unsigned char signature_compressed[SIG_COMPRESS_MAX_LEN];
} x509_cert_t;


int x509_to_cbor(x509_cert_t *cert_to_cbor);
