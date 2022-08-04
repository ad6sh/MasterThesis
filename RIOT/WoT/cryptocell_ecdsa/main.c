/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       this is an ecdsa test application for cryptocell
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "cryptocell_util.h"

#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/crys_ecpki_build.h"
#include "cryptocell_incl/crys_ecpki_ecdsa.h"
#include "cryptocell_incl/crys_ecpki_kg.h"
#include "cryptocell_incl/crys_ecpki_domain.h"

#ifdef TEST_STACK
#include "ps.h"
#endif

#if !defined(COSY_TEST) && !defined(TEST_STACK)
#include "xtimer.h"
#include "periph/gpio.h"

gpio_t active_gpio = GPIO_PIN(1, 7);
gpio_t gpio_aes_key = GPIO_PIN(1, 8);
gpio_t gpio_sync_pin = GPIO_PIN(1, 6);

#define ITERATIONS                  (50)

static inline void _init_trigger(void)
{
#if TEST_ENERGY
    gpio_init(active_gpio, GPIO_OUT);
    gpio_init(gpio_aes_key, GPIO_OUT);
    gpio_init(gpio_sync_pin, GPIO_IN);

    gpio_set(active_gpio);
    gpio_clear(gpio_aes_key);
#else
    gpio_init(active_gpio, GPIO_OUT);
    gpio_clear(active_gpio);
#endif
}

static inline void _start_trigger(void)
{
#if TEST_ENERGY
    while(gpio_read(gpio_sync_pin)) {};
    while(!gpio_read(gpio_sync_pin)) {};
    gpio_clear(active_gpio);
#else
    gpio_set(active_gpio);
#endif
}

static inline void _stop_trigger(void)
{
#if TEST_ENERGY
    gpio_set(gpio_aes_key);

    gpio_set(active_gpio);
    gpio_clear(gpio_aes_key);
#else
    gpio_clear(active_gpio);
#endif
}


#endif

#define SHA256_DIGEST_SIZE          (32)
#define ECDSA_MESSAGE_SIZE          (127)

extern CRYS_RND_State_t*     rndState_ptr;

CRYS_ECPKI_UserPrivKey_t UserPrivKey;
CRYS_ECPKI_UserPublKey_t UserPublKey;

CRYS_ECPKI_Domain_t* pDomain;
SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc;
uint32_t ecdsa_sig_size = 64;



void _init_vars(void)
{
    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
}


void _gen_keypair(void)
{
CRYS_ECPKI_KG_FipsContext_t FipsBuff;
CRYS_ECPKI_KG_TempData_t TempECCKGBuff;
#if !defined(COSY_TEST) && !defined(TEST_STACK)
    int ret = 0;

    _start_trigger();
    cryptocell_enable();
    ret = CRYS_ECPKI_GenKeyPair(rndState_ptr, rndGenerateVectFunc, pDomain, &UserPrivKey, &UserPublKey, &TempECCKGBuff, &FipsBuff);
    cryptocell_disable();
    _stop_trigger();

    if (ret != SA_SILIB_RET_OK){
        printf("CRYS_ECPKI_GenKeyPair for key pair 1 failed with 0x%x \n",ret);
        return;
    }
#else
    cryptocell_enable();
    CRYS_ECPKI_GenKeyPair(rndState_ptr, rndGenerateVectFunc, pDomain, &UserPrivKey, &UserPublKey, &TempECCKGBuff, &FipsBuff);
    cryptocell_disable();
#endif
}

void _sign_verify(void)
{
    CRYS_ECDSA_SignUserContext_t SignUserContext;
    CRYS_ECDSA_VerifyUserContext_t VerifyUserContext;
    CRYS_ECDH_TempData_t signOutBuff;

    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };

#if !defined(COSY_TEST) && !defined(TEST_STACK)
    int ret = 0;
    /*Call CRYS_ECDSA_Sign to create signature from input buffer using created private key*/
    _start_trigger();
    cryptocell_enable();
    ret = CRYS_ECDSA_Sign (rndState_ptr, rndGenerateVectFunc,
    &SignUserContext, &UserPrivKey, CRYS_ECPKI_HASH_SHA256_mode, msg, sizeof(msg), (uint8_t*)&signOutBuff, &ecdsa_sig_size);
    cryptocell_disable();
    _stop_trigger();

    if (ret != SA_SILIB_RET_OK){
        printf("CRYS_ECDSA_Sign failed with 0x%x \n",ret);
        return;
    }

    _start_trigger();
    cryptocell_enable();
    ret =  CRYS_ECDSA_Verify (&VerifyUserContext, &UserPublKey, CRYS_ECPKI_HASH_SHA256_mode, (uint8_t*)&signOutBuff, ecdsa_sig_size, msg, sizeof(msg));
    cryptocell_disable();
    _stop_trigger();

    if (ret != SA_SILIB_RET_OK){
        printf("CRYS_ECDSA_Verify failed with 0x%x \n",ret);
        return;
    }
    puts("VALID");
#else
    cryptocell_enable();
    CRYS_ECDSA_Sign (rndState_ptr, rndGenerateVectFunc,
    &SignUserContext, &UserPrivKey, CRYS_ECPKI_HASH_SHA256_mode, msg, sizeof(msg), (uint8_t*)&signOutBuff, &ecdsa_sig_size);
    cryptocell_disable();

    cryptocell_enable();
    CRYS_ECDSA_Verify (&VerifyUserContext, &UserPublKey, CRYS_ECPKI_HASH_SHA256_mode, (uint8_t*)&signOutBuff, ecdsa_sig_size, msg, sizeof(msg));
    cryptocell_disable();
#endif
}

int main(void)
{
#if !defined(COSY_TEST) && !defined(TEST_STACK)
    puts("'crypto-ewsn2020_ecdsa cryptocell'");

    _init_trigger();

    // xtimer_sleep(1);

    for (int i = 0; i < ITERATIONS; i++) {
        _start_trigger();
        _init_vars();
        _stop_trigger();
#else
    _init_vars();
#endif

        // generate keypairs
        _gen_keypair();

        // sign data and verify with public ley
        _sign_verify();

#if !defined(COSY_TEST) && !defined(TEST_STACK)
    }
#endif
#ifdef TEST_STACK
    ps();
    printf("sizeof(UserPrivKey): %i\n", sizeof(UserPrivKey));
    printf("sizeof(UserPubKey): %i\n", sizeof(UserPublKey));
    printf("sizeof(UserPrivKey.PrivKeyDbBuff): %i\n", sizeof(UserPrivKey.PrivKeyDbBuff));
    printf("sizeof(UserPrivKey.PrivKeyDbBuff.valid_tag): %i\n", sizeof(UserPrivKey.valid_tag));
    printf("sizeof(CRYS_ECPKI_Domain_t): %i\n", sizeof(CRYS_ECPKI_Domain_t));
    printf("sizeof(CRYS_ECPKI_ScaProtection_t): %i\n", sizeof(CRYS_ECPKI_ScaProtection_t));
    printf("sizeof(UserPubKey.PublKeyDbBuff): %i\n", sizeof(UserPublKey.PublKeyDbBuff));
    printf("sizeof(CRYS_ECDSA_SignUserContext_t): %i\n", sizeof(CRYS_ECDSA_SignUserContext_t));
    printf("sizeof(CRYS_ECDSA_VerifyUserContext_t): %i\n", sizeof(CRYS_ECDSA_VerifyUserContext_t));
    puts("");

    printf("UserPrivKey: %i\n", sizeof(UserPrivKey));
    printf("UserPublKey: %i\n", sizeof(UserPublKey));
    printf("signOutBuff: %i\n", sizeof(CRYS_ECDH_TempData_t));
    printf("SignUserContext: %i\n", sizeof(CRYS_ECDSA_SignUserContext_t));
    printf("VerifyUserContext: %i\n", sizeof(CRYS_ECDSA_VerifyUserContext_t));
    printf("TempECCKGBuff: %i\n", sizeof(CRYS_ECPKI_KG_TempData_t));
    printf("FipsBuff: %i\n", sizeof(CRYS_ECPKI_KG_FipsContext_t));
    printf("rndGenerateVectFunc: %i\n", sizeof(SaSiRndGenerateVectWorkFunc_t));

#endif
    puts("DONE");
    return 0;
}


