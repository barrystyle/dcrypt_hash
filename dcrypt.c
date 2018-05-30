#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "dcrypt.h"

#define REALLOC_BASE_SZ   (1024)

typedef struct {
  uint8_t *array;
  unsigned long long actual_array_sz;
  uint32_t times_realloced;
} Extend_Array;

inline void Extend_Array_init(Extend_Array *ExtArray) {
  ExtArray->array = 0;
  ExtArray->actual_array_sz = 0;
  ExtArray->times_realloced = 0;
  return;
}

uint32_t hex_char_to_int(uint8_t c) {
  if(c > 47 && c < 58)  return c - 47;
  if(c > 96 && c < 103) return 10 + c - 96;
  if(c > 64 && c < 71)  return 10 + c - 64;
  return 0;
}

inline void join_to_array(uint8_t *array, uint8_t join) {
  *(array + SHA256_LEN) = join;
  return;
}

void extend_array(Extend_Array *extend_array, unsigned long long used_array_sz, uint8_t *extend, uint32_t extend_sz, uint8_t hashed_end) {
  if(!extend_array)
    return;
  if((extend_array->actual_array_sz - used_array_sz) < (extend_sz + hashed_end))
  {
    if(extend_array->times_realloced)
    {
      extend_array->actual_array_sz += (2 << extend_array->times_realloced++) * REALLOC_BASE_SZ;
      extend_array->array = realloc(extend_array->array, extend_array->actual_array_sz);
    }else{
      extend_array->actual_array_sz += REALLOC_BASE_SZ;
      extend_array->times_realloced++;
      extend_array->array = malloc(extend_array->actual_array_sz);
    }
  }
  memcpy(extend_array->array + used_array_sz, extend, extend_sz);
  if(hashed_end)   
    *(extend_array->array + used_array_sz + extend_sz) = 0;
  return;
}

uint64_t mix_hashed_nums(uint8_t *hashed_nums, const uint8_t *unhashedData, size_t unhashed_sz, uint8_t **mixed_hash, uint8_t *hash_digest) {
  uint32_t index = 0;
  const uint32_t hashed_nums_len = SHA256_LEN;
  uint64_t count;
  uint8_t tmp_val, tmp_array[SHA256_LEN + 2];
  Extend_Array new_hash;
  Extend_Array_init(&new_hash);
  memset(tmp_array, 0xff, SHA256_LEN);
  *(tmp_array + SHA256_LEN) = *(tmp_array + SHA256_LEN + 1) = 0;
  for(count = 0;; count++)
  {
    index += hex_char_to_int(*(hashed_nums + index));
    if(index >= hashed_nums_len) {
      index = index & (hashed_nums_len - 1);
      sha256_to_str(hashed_nums, hashed_nums_len, hashed_nums, hash_digest);
    }
    tmp_val = *(hashed_nums + index);
    join_to_array(tmp_array, tmp_val);
    sha256_to_str(tmp_array, SHA256_LEN + 1, tmp_array, hash_digest);
    extend_array(&new_hash, count * SHA256_LEN, tmp_array, SHA256_LEN, false);
    if(index == hashed_nums_len - 1 && tmp_val == *(tmp_array + SHA256_LEN - 1)) {
      count++;
      break;
    }
  }
  extend_array(&new_hash, count * SHA256_LEN, (uint8_t*)unhashedData, unhashed_sz, true);
  *mixed_hash = new_hash.array;
  return count * SHA256_LEN + unhashed_sz;
}

uint8_t *dcrypt_buffer_alloc() {
  return malloc(DCRYPT_DIGEST_LENGTH);
}

void dcrypt(const uint8_t *data, size_t data_sz, uint8_t *hash_digest, uint32_t *hashRet) {
  uint8_t hashed_nums[SHA256_LEN + 1], *mix_hash;
  sha256_to_str(data, data_sz, hashed_nums, hash_digest);
  uint64_t mix_hash_len = mix_hashed_nums(hashed_nums, data, data_sz, &mix_hash, hash_digest);
  sha256_dcrypt((const uint8_t*)mix_hash, mix_hash_len, hashRet);
  free(mix_hash);
  return;
}

void dcrypt_hash(char* input, char* output, int32_t len) {
  dcrypt(input, len, 0, (char *) output);
}

void digest_to_string(uint8_t *hash_digest, uint8_t *string) {
  register uint8_t tmp_val;
  uint8_t i = 0, *ps;
  for(; i < SHA256_DIGEST_LENGTH; i++) {
    ps = string + i * 2;
    tmp_val = *(hash_digest + i) >> 4;
    if(tmp_val < 10)
      *ps = tmp_val + 48;
    else
      *ps = tmp_val + 87;
    tmp_val = *(hash_digest + i) & 0xf;
    if(tmp_val < 10)
      *(ps + 1) = tmp_val + 48;
    else
      *(ps + 1) = tmp_val + 87;
  }
  *(string + SHA256_LEN) = 0;
  return;
}

void sha256_to_str(const uint8_t *data, size_t data_sz, uint8_t *outputBuffer, uint8_t *hash_digest) {
  SHA256_CTX sha256;
  static uint8_t __digest__[SHA256_DIGEST_LENGTH];
  if(hash_digest == NULL)
    hash_digest = __digest__;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, data, data_sz);
  SHA256_Final(hash_digest, &sha256);
  digest_to_string(hash_digest, outputBuffer);
  return;
}

uint32_t *sha256_dcrypt(const uint8_t *data, size_t data_sz, uint32_t *hash_digest) {
  SHA256_CTX hash;
  SHA256_Init(&hash);
  SHA256_Update(&hash, data, data_sz);
  SHA256_Final((uint8_t*)hash_digest, &hash);
  return hash_digest;
}
