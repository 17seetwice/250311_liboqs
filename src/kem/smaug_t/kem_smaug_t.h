// // SPDX-License-Identifier: MIT

// #ifndef OQS_KEM_SMAUG_T_H
// #define OQS_KEM_SMAUG_T_H

// #include <oqs/oqs.h>

// #if defined(OQS_ENABLE_KEM_smaug_t_1)
// #define OQS_KEM_smaug_t_1_length_public_key 672
// #define OQS_KEM_smaug_t_1_length_secret_key 160+672
// #define OQS_KEM_smaug_t_1_length_ciphertext 672
// #define OQS_KEM_smaug_t_1_length_shared_secret 32
// OQS_KEM *OQS_KEM_smaug_t_1_new(void);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_1_keypair(uint8_t *public_key, uint8_t *secret_key);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_1_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_1_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
// #endif

// #if defined(OQS_ENABLE_KEM_smaug_t_3)
// #define OQS_KEM_smaug_t_3_length_public_key 1088
// #define OQS_KEM_smaug_t_3_length_secret_key 244+1088
// #define OQS_KEM_smaug_t_3_length_ciphertext 992
// #define OQS_KEM_smaug_t_3_length_shared_secret 32
// OQS_KEM *OQS_KEM_smaug_t_3_new(void);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_3_keypair(uint8_t *public_key, uint8_t *secret_key);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_3_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_3_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
// #endif

// #if defined(OQS_ENABLE_KEM_smaug_t_5)
// #define OQS_KEM_smaug_t_5_length_public_key 1440
// #define OQS_KEM_smaug_t_5_length_secret_key 352+1440
// #define OQS_KEM_smaug_t_5_length_ciphertext 1376
// #define OQS_KEM_smaug_t_5_length_shared_secret 32
// OQS_KEM *OQS_KEM_smaug_t_5_new(void);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_5_keypair(uint8_t *public_key, uint8_t *secret_key);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_5_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
// OQS_API OQS_STATUS OQS_KEM_smaug_t_5_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
// #endif

// #endif

// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_SMAUG_T_H
#define OQS_KEM_SMAUG_T_H

#include <oqs/oqs.h>
#include "api.h"  // API 헤더 파일 포함

#if defined(OQS_ENABLE_KEM_smaug_t_1)
#define OQS_KEM_smaug_t_1_length_public_key cryptolab_smaug1_PUBLICKEYBYTES
#define OQS_KEM_smaug_t_1_length_secret_key cryptolab_smaug1_SECRETKEYBYTES
#define OQS_KEM_smaug_t_1_length_ciphertext cryptolab_smaug1_CIPHERTEXTBYTES
#define OQS_KEM_smaug_t_1_length_shared_secret cryptolab_smaug1_BYTES
OQS_KEM *OQS_KEM_smaug_t_1_new(void);
OQS_API OQS_STATUS OQS_KEM_smaug_t_1_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaug_t_1_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaug_t_1_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_smaug_t_3)
#define OQS_KEM_smaug_t_3_length_public_key cryptolab_smaug3_PUBLICKEYBYTES
#define OQS_KEM_smaug_t_3_length_secret_key cryptolab_smaug3_SECRETKEYBYTES
#define OQS_KEM_smaug_t_3_length_ciphertext cryptolab_smaug3_CIPHERTEXTBYTES
#define OQS_KEM_smaug_t_3_length_shared_secret cryptolab_smaug3_BYTES
OQS_KEM *OQS_KEM_smaug_t_3_new(void);
OQS_API OQS_STATUS OQS_KEM_smaug_t_3_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaug_t_3_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaug_t_3_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_smaug_t_5)
#define OQS_KEM_smaug_t_5_length_public_key cryptolab_smaug5_PUBLICKEYBYTES
#define OQS_KEM_smaug_t_5_length_secret_key cryptolab_smaug5_SECRETKEYBYTES
#define OQS_KEM_smaug_t_5_length_ciphertext cryptolab_smaug5_CIPHERTEXTBYTES
#define OQS_KEM_smaug_t_5_length_shared_secret cryptolab_smaug5_BYTES
OQS_KEM *OQS_KEM_smaug_t_5_new(void);
OQS_API OQS_STATUS OQS_KEM_smaug_t_5_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaug_t_5_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaug_t_5_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#endif // OQS_KEM_SMAUG_T_H
