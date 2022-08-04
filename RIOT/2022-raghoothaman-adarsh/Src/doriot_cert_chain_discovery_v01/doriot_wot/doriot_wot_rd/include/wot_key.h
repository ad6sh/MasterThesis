
#ifndef WOT_KEY_H
#define WOT_KEY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PUB_KEY_SIZE 64
extern uint8_t wot_public_key[PUB_KEY_SIZE];

/**
 * @brief function to provision public key from app
 * 
 * @param pub_key 
 * @return int 
 */
int wot_provision_pub_key(uint8_t *pub_key);


#ifdef __cplusplus
}
#endif

#endif /* WOT_KEY_H */
