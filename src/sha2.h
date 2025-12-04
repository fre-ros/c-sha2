#ifndef SHA2_H_
#define SHA2_H_

#include <stdint.h>
#include <stddef.h>

#define SHA224_HASH_LEN     28U
#define SHA256_HASH_LEN     32U
#define SHA384_HASH_LEN     48U
#define SHA512_HASH_LEN     64U
#define SHA512_224_HASH_LEN 28U
#define SHA512_256_HASH_LEN 32U

#define SHA224_STR_LEN     ((SHA224_HASH_LEN * 2U) + 1U)
#define SHA256_STR_LEN     ((SHA256_HASH_LEN * 2U) + 1U)
#define SHA384_STR_LEN     ((SHA384_HASH_LEN * 2U) + 1U)
#define SHA512_STR_LEN     ((SHA512_HASH_LEN * 2U) + 1U)
#define SHA512_224_STR_LEN ((SHA512_224_HASH_LEN * 2U) + 1U)
#define SHA512_256_STR_LEN ((SHA512_256_HASH_LEN * 2U) + 1U)

/*************************
 *    SHA2xx context
 ************************/
typedef struct {
  size_t chunk_idx;
  uint64_t msg_len;
  uint32_t h[8U];
  uint8_t chunk[64U];
} sha256_ctx;

typedef sha256_ctx sha224_ctx;

/*************************
 *    SHA5xx context
 ************************/
typedef struct {
  size_t chunk_idx;
  uint64_t msg_len_low;
  uint64_t msg_len_high;
  uint64_t h[8U];
  uint8_t chunk[128U];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;
typedef sha512_ctx sha512_224_ctx;
typedef sha512_ctx sha512_256_ctx;

/*************************
 *        SHA224
 ************************/
extern void sha224(const uint8_t *data, size_t size, uint8_t result[static SHA224_HASH_LEN]);
extern void sha224_init(sha224_ctx *ctx);
extern void sha224_process(sha224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha224_finalize(sha224_ctx *ctx, uint8_t result[static SHA224_HASH_LEN]);
extern char* sha224_to_str(const uint8_t hash[static SHA224_HASH_LEN]);
extern void sha224_to_str_buffer(const uint8_t hash[static SHA224_HASH_LEN], char dst[static SHA224_STR_LEN]);

/*************************
 *        SHA256
 ************************/
extern void sha256(const uint8_t *data, size_t size, uint8_t result[static SHA256_HASH_LEN]);
extern void sha256_init(sha256_ctx *ctx);
extern void sha256_process(sha256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha256_finalize(sha256_ctx *ctx, uint8_t result[static SHA256_HASH_LEN]);
extern char* sha256_to_str(const uint8_t hash[static SHA256_HASH_LEN]);
extern void sha256_to_str_buffer(const uint8_t hash[static SHA256_HASH_LEN], char dst[static SHA256_STR_LEN]);

/*************************
 *        SHA384
 ************************/
extern void sha384(const uint8_t *data, size_t size, uint8_t result[static SHA384_HASH_LEN]);
extern void sha384_init(sha384_ctx *ctx);
extern void sha384_process(sha384_ctx *ctx, const uint8_t *data, size_t size);
extern void sha384_finalize(sha384_ctx *ctx, uint8_t result[static SHA384_HASH_LEN]);
extern char* sha384_to_str(const uint8_t hash[static SHA384_HASH_LEN]);
extern void sha384_to_str_buffer(const uint8_t hash[static SHA384_HASH_LEN], char dst[static SHA384_STR_LEN]);

/*************************
 *        SHA512
 ************************/
extern void sha512(const uint8_t *data, size_t size, uint8_t result[static SHA512_HASH_LEN]);
extern void sha512_init(sha512_ctx *ctx);
extern void sha512_process(sha512_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_finalize(sha512_ctx *ctx, uint8_t result[static SHA512_HASH_LEN]);
extern char* sha512_to_str(const uint8_t hash[static SHA512_HASH_LEN]);
extern void sha512_to_str_buffer(const uint8_t hash[static SHA512_HASH_LEN], char dst[static SHA512_STR_LEN]);

/*************************
 *      SHA512/224
 ************************/
extern void sha512_224(const uint8_t *data, size_t size, uint8_t result[static SHA512_224_HASH_LEN]);
extern void sha512_224_init(sha512_224_ctx *ctx);
extern void sha512_224_process(sha512_224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_224_finalize(sha512_224_ctx *ctx, uint8_t result[static SHA512_224_HASH_LEN]);
extern char* sha512_224_to_str(const uint8_t hash[static SHA512_224_HASH_LEN]);
extern void sha512_224_to_str_buffer(const uint8_t hash[static SHA512_224_HASH_LEN], char dst[static SHA512_224_STR_LEN]);

/*************************
 *      SHA512/256
 ************************/
extern void sha512_256(const uint8_t *data, size_t size, uint8_t result[static SHA512_256_HASH_LEN]);
extern void sha512_256_init(sha512_256_ctx *ctx);
extern void sha512_256_process(sha512_256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_256_finalize(sha512_256_ctx *ctx, uint8_t result[static SHA512_256_HASH_LEN]);
extern char* sha512_256_to_str(const uint8_t hash[static SHA512_256_HASH_LEN]);
extern void sha512_256_to_str_buffer(const uint8_t hash[static SHA512_256_HASH_LEN], char dst[static SHA512_256_STR_LEN]);

#endif /* SHA2_H_ */
