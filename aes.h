#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

// Modified version of tiny-AES by kkoke
// https://github.com/kokke/tiny-AES-c
//

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only
#define AES_256_KEYLEN 32
#define AES_256_keyExpSize 240
#define AES_128_KEYLEN 16 // Key length in bytes
#define AES_128_keyExpSize 176

struct AES_ctx
{
  uint8_t RoundKey[AES_256_keyExpSize];
  uint8_t Iv[AES_BLOCKLEN];
  bool isAES256;
};

void AES_init_ctx(struct AES_ctx* ctx, const char* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const char* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

// buffer size MUST be mutile of AES_BLOCKLEN;
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt_buffer(struct AES_ctx* ctx, const uint8_t* buf, uint32_t length);
void AES_ECB_decrypt_buffer(struct AES_ctx* ctx, const uint8_t* buf, uint32_t length);

// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);

#endif //_AES_H_
