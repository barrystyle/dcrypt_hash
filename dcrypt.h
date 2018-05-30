#ifndef DCRYPT_H
#define DCRYPT_H

#include "sha256.h"

#define DCRYPT_DIGEST_LENGTH 64
#define SHA256_LEN           64
#define SHA256_DIGEST_LENGTH 32

void dcrypt(const uint8_t *data, size_t data_sz, uint8_t *hash_digest, uint32_t *hashRet);
uint8_t *dcrypt_buffer_alloc();
void dcrypt_hash(char* input, char* output, int32_t len);
void sha256_to_str(const uint8_t *data, size_t data_sz, uint8_t *outputBuffer, uint8_t *hash_digest);
uint32_t *sha256_dcrypt(const uint8_t *data, size_t data_sz, uint32_t *hash_digest);
void digest_to_string(uint8_t *hash_digest, uint8_t *string);

#endif
