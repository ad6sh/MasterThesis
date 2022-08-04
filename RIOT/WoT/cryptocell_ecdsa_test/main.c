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
#include <string.h>
#include "msg.h"
#include "shell.h"
#include "xtimer.h"
#define MAIN_QUEUE_SIZE (4)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#include "cryptocell_util.h"

#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/crys_ecpki_build.h"
#include "cryptocell_incl/crys_ecpki_ecdsa.h"
//#include "cryptocell_incl/crys_ecpki_kg.h"
#include "cryptocell_incl/crys_ecpki_domain.h"


//#include "ps.h"
//#include "xtimer.h"
//#include "periph/gpio.h"

#define SHA256_DIGEST_SIZE          (32)
#define ECDSA_MESSAGE_SIZE          (127)

extern CRYS_RND_State_t*     rndState_ptr;

CRYS_ECPKI_UserPrivKey_t UserPrivKey;
CRYS_ECPKI_UserPublKey_t UserPublKey;

CRYS_ECPKI_Domain_t* pDomain;
SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc;
uint32_t ecdsa_sig_size = 64;

uint32_t start_time;
uint32_t end_time;


void _init_vars(void)
{
    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
}


static unsigned char priv_key[] = {
    0x41, 0x90, 0xA3, 0xC1, 0xD0, 0x09, 0xD7, 0x74, 0x96, 0x6B, 0x53, 0x51, 0x2E, 0x76, 0xDF, 0x5A,
    0x40, 0x1B, 0xE3, 0x4F, 0xBA, 0x55, 0x8C, 0x13, 0x26, 0xE2, 0x7F, 0xDD, 0xCB, 0x6A, 0xDE, 0x06

};

/**
 * @brief public need 0x04 as first byte so total 65 
 * 
 */
static unsigned char pub_key[] = {
    0x04,0x46, 0x96, 0xFA, 0xCD, 0x14, 0xE9, 0xE3, 0x76, 0x28, 0x35, 0x94, 0x89, 0x9D, 0x48, 0x19, 0x74,
    0x0E, 0x25, 0x0E, 0x75, 0xF5, 0x2C, 0xB3, 0x29, 0x19, 0xFB, 0x5B, 0x80, 0x2B, 0x8F, 0xC0, 0xD7,
    0x2B, 0x9E, 0x09, 0x67, 0x37, 0x88, 0xCC, 0x69, 0xF4, 0xA9, 0xA9, 0x32, 0x60, 0xE5, 0x75, 0x88,
    0x22, 0x0C, 0x2C, 0xD9, 0x34, 0x55, 0x7E, 0xC3, 0x0E, 0xDA, 0x33, 0x5D, 0x77, 0x16, 0xA6, 0x78

};




void _copy_keys(void)
{
    int ret=0; 
    cryptocell_enable();
    ret = CRYS_ECPKI_BuildPrivKey(pDomain,priv_key,(uint32_t)32,&UserPrivKey);
    cryptocell_disable(); 	
    if (ret != CRYS_OK)
    {
        printf("failed to copy private key\n");
        return;
    }
    else
    {
        printf("copied private key\n");
    }

    CRYS_ECPKI_BUILD_TempData_t pTempBuff;
    cryptocell_enable();
    ret = _DX_ECPKI_BuildPublKey(pDomain,pub_key,(uint32_t)65,0,&UserPublKey,&pTempBuff);
    cryptocell_disable();	
    if (ret != CRYS_OK)
    {
        printf("failed to copy public key");
        return;
    }
    else
    {
        printf("copied public key\n");
    
    }
    cryptocell_disable();
    printf("copied keys\n :)");

}


/*void _gen_keypair(void)
{
CRYS_ECPKI_KG_FipsContext_t FipsBuff;
CRYS_ECPKI_KG_TempData_t TempECCKGBuff;
    int ret = 0;

    cryptocell_enable();
    ret = CRYS_ECPKI_GenKeyPair(rndState_ptr, rndGenerateVectFunc, pDomain, &UserPrivKey, &UserPublKey, &TempECCKGBuff, &FipsBuff);
    cryptocell_disable();
    
    if (ret != SA_SILIB_RET_OK){
        printf("CRYS_ECPKI_GenKeyPair for key pair 1 failed with 0x%x \n",ret);
        return;
    }
    else
    {
        printf("KeyPair generation Success\n");
    }
}*/

void _sign_verify(void)
{
    CRYS_ECDSA_SignUserContext_t SignUserContext;
    CRYS_ECDSA_VerifyUserContext_t VerifyUserContext;
    CRYS_ECDH_TempData_t signOutBuff;
    int ret = 0;
    
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };

    start_time = xtimer_now_usec();
    cryptocell_enable();
    ret = CRYS_ECDSA_Sign(rndState_ptr, rndGenerateVectFunc,
    &SignUserContext, &UserPrivKey, CRYS_ECPKI_HASH_SHA256_mode, msg, sizeof(msg), (uint8_t*)&signOutBuff, &ecdsa_sig_size);
    cryptocell_disable();
    end_time = xtimer_now_usec();
    printf("sign time: %ld\n", (end_time - start_time));

    if (ret != SA_SILIB_RET_OK){
        printf("CRYS_ECDSA_Sign failed with 0x%x \n",ret);
        return;
    }

    start_time = xtimer_now_usec();
    cryptocell_enable();
    ret =  CRYS_ECDSA_Verify (&VerifyUserContext, &UserPublKey, CRYS_ECPKI_HASH_SHA256_mode, (uint8_t*)&signOutBuff, ecdsa_sig_size, msg, sizeof(msg));
    cryptocell_disable();
    end_time = xtimer_now_usec();
    printf("verify time: %ld\n", (end_time - start_time));

    if (ret != SA_SILIB_RET_OK){
        printf("CRYS_ECDSA_Verify failed with 0x%x \n",ret);
        return;
    }

    puts("Signing and Verification Success!\n");
}


int test_cmd_app(int argc,char **argv)
{
(void)argc;
(void)argv;
puts("'crypto-ewsn2020_ecdsa cryptocell'");
_init_vars();
// generate keypairs
//_gen_keypair();
_copy_keys();
// sign data and verify with public ley
_sign_verify();
 return 0;
}

static const shell_command_t shell_commands[] = {
    { "test", "test command", test_cmd_app },
    { NULL, NULL, NULL }
};


int main(void)
{
     /* for the thread running the shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should never be reached */
    return 0;
}


