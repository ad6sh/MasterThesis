

#ifndef KEYS_H
#define KEYS_H


#ifdef __cplusplus
extern "C" {
#endif


#define TEST_NAME "alice"


extern uint8_t ecdsa_priv_key[32];
extern uint8_t ecdsa_pub_key[64];




static  unsigned char ecdsa_priv_key_new0[] = {
    0x41, 0x90, 0xA3, 0xC1, 0xD0, 0x09, 0xD7, 0x74, 0x96, 0x6B, 0x53, 0x51, 0x2E, 0x76, 0xDF, 0x5A,
    0x40, 0x1B, 0xE3, 0x4F, 0xBA, 0x55, 0x8C, 0x13, 0x26, 0xE2, 0x7F, 0xDD, 0xCB, 0x6A, 0xDE, 0x06
};


static  unsigned char ecdsa_pub_key_new0[] = {
    0x46, 0x96, 0xFA, 0xCD, 0x14, 0xE9, 0xE3, 0x76, 0x28, 0x35, 0x94, 0x89, 0x9D, 0x48, 0x19, 0x74,
    0x0E, 0x25, 0x0E, 0x75, 0xF5, 0x2C, 0xB3, 0x29, 0x19, 0xFB, 0x5B, 0x80, 0x2B, 0x8F, 0xC0, 0xD7,
    0x2B, 0x9E, 0x09, 0x67, 0x37, 0x88, 0xCC, 0x69, 0xF4, 0xA9, 0xA9, 0x32, 0x60, 0xE5, 0x75, 0x88,
    0x22, 0x0C, 0x2C, 0xD9, 0x34, 0x55, 0x7E, 0xC3, 0x0E, 0xDA, 0x33, 0x5D, 0x77, 0x16, 0xA6, 0x78
};


static  unsigned char ecdsa_priv_key_new1[] = {
    0x3A, 0x8D, 0xFF, 0xFB, 0xAE, 0x7D, 0x8F, 0xA4, 0xAF, 0x3F, 0x37, 0x8E, 0x14, 0x2C, 0x60, 0x2C,
    0x9C, 0xDD, 0x01, 0xE3, 0x2C, 0xD7, 0xCD, 0x3A, 0xE7, 0xF7, 0x36, 0x1C, 0xFD, 0xBF, 0x61, 0x89
};


static  unsigned char ecdsa_pub_key_new1[] = {
    0x6E, 0x0B, 0xD3, 0xE6, 0x92, 0x58, 0xB4, 0x38, 0x82, 0xC6, 0xAE, 0x0B, 0xE1, 0x9F, 0x50, 0x4A,
    0xB2, 0x40, 0x6D, 0xE3, 0xCB, 0xC2, 0x93, 0x27, 0x4E, 0x59, 0x37, 0x36, 0xC0, 0x80, 0xC1, 0x73,
    0x06, 0xDE, 0x7C, 0x6E, 0x4E, 0xC8, 0x6B, 0xD5, 0x92, 0xDE, 0x98, 0x09, 0x1B, 0x06, 0x2A, 0x8C,
    0x68, 0x6F, 0x9E, 0xAF, 0x74, 0x47, 0x58, 0x86, 0xD8, 0x2C, 0x17, 0x68, 0xF4, 0x69, 0xB5, 0x0F
};













static uint8_t psk_key[] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

static const unsigned char rd_ecdsa_priv_key[] = {
    0x41, 0xC1, 0xCB, 0x6B, 0x51, 0x24, 0x7A, 0x14,
    0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14,
    0x89, 0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA,
    0x40, 0x14, 0x55, 0xA1, 0x94, 0xA9, 0x49, 0xFA
};

static const unsigned char rd_ecdsa_pub_key_x[] = {
    0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
    0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
    0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
    0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52
};

static const unsigned char rd_ecdsa_pub_key_y[] = {
    0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
    0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
    0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
    0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29
};

static const unsigned char cli_ecdsa_priv_key[] = {
    0x99, 0x1b, 0x1c, 0xf1, 0x52, 0xa3, 0xf5, 0xac,
    0xce, 0x58, 0x00, 0x45, 0xdc, 0xa7, 0x45, 0x45,
    0x9e, 0xc6, 0xd8, 0x68, 0x21, 0xd4, 0x82, 0xb7,
    0x17, 0x84, 0x0a, 0xdc, 0x1d, 0xf1, 0x09, 0x57
};

static const unsigned char cli_ecdsa_pub_key_x[] = {
    0xb7, 0x4e, 0xa0, 0x62, 0x96, 0xc5, 0xb9, 0x09,
    0xad, 0x36, 0x10, 0xab, 0xb1, 0xd8, 0x54, 0x69,
    0xef, 0x2b, 0x15, 0x5a, 0xb5, 0x28, 0x21, 0x21,
    0x9f, 0xa3, 0x9e, 0x6a, 0x02, 0xce, 0xb8, 0xb9
};

static const unsigned char cli_ecdsa_pub_key_y[] = {
    0xcc, 0x0e, 0x88, 0x88, 0x91, 0x80, 0x7a, 0xdd,
    0xf7, 0x4e, 0x2e, 0xe6, 0x6e, 0xd4, 0x22, 0xde,
    0xbc, 0x68, 0xcd, 0x8f, 0xd9, 0x5a, 0xa0, 0xcd,
    0x5f, 0x4a, 0x1a, 0xb7, 0x2f, 0x95, 0xfc, 0x76
};





int wot_create_keys(void );

int wot_print_keys(void );





#ifdef __cplusplus
}
#endif

#endif /*KEYS_H */
