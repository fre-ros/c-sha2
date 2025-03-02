#ifndef SHA2_H_
#define SHA2_H_

#include <stdint.h>
#include <stddef.h>

/*************************
 *    SHA2xx context
 ************************/
typedef struct {
  size_t msg_len;
  size_t chunk_idx;
  uint32_t h[8U];
  uint8_t chunk[64U];
} sha256_ctx;

typedef sha256_ctx sha224_ctx;

/*************************
 *    SHA5xx context
 ************************/
typedef struct {
  size_t msg_len;
  size_t chunk_idx;
  uint64_t h[8U];
  uint8_t chunk[128U];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;
typedef sha512_ctx sha512_224_ctx;
typedef sha512_ctx sha512_256_ctx;

/*************************
 *        SHA224
 ************************/
extern void sha224(const uint8_t *data, size_t size, uint8_t result[static 28U]);
extern void sha224_init(sha224_ctx *ctx);
extern void sha224_process(sha224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha224_finalize(sha224_ctx *ctx, uint8_t result[static 28U]);
extern char* sha224_to_string(const uint8_t hash[static 28U]);

/*************************
 *        SHA256
 ************************/
extern void sha256(const uint8_t *data, size_t size, uint8_t result[static 32U]);
extern void sha256_init(sha256_ctx *ctx);
extern void sha256_process(sha256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha256_finalize(sha256_ctx *ctx, uint8_t result[static 32U]);
extern char* sha256_to_string(const uint8_t hash[static 32U]);

/*************************
 *        SHA384
 ************************/
extern void sha384(const uint8_t *data, size_t size, uint8_t result[static 48U]);
extern void sha384_init(sha384_ctx *ctx);
extern void sha384_process(sha384_ctx *ctx, const uint8_t *data, size_t size);
extern void sha384_finalize(sha384_ctx *ctx, uint8_t result[static 48U]);
extern char* sha384_to_string(const uint8_t hash[static 48U]);

/*************************
 *        SHA512
 ************************/
extern void sha512(const uint8_t *data, size_t size, uint8_t result[static 64U]);
extern void sha512_init(sha512_ctx *ctx);
extern void sha512_process(sha512_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_finalize(sha512_ctx *ctx, uint8_t result[static 64U]);
extern char* sha512_to_string(const uint8_t hash[static 64U]);

/*************************
 *      SHA512/224
 ************************/
extern void sha512_224(const uint8_t *data, size_t size, uint8_t result[static 28U]);
extern void sha512_224_init(sha512_224_ctx *ctx);
extern void sha512_224_process(sha512_224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_224_finalize(sha512_224_ctx *ctx, uint8_t result[static 28U]);
extern char* sha512_224_to_string(const uint8_t hash[static 28U]);

/*************************
 *      SHA512/256
 ************************/
extern void sha512_256(const uint8_t *data, size_t size, uint8_t result[static 32U]);
extern void sha512_256_init(sha512_256_ctx *ctx);
extern void sha512_256_process(sha512_256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_256_finalize(sha512_256_ctx *ctx, uint8_t result[static 32U]);
extern char* sha512_256_to_string(const uint8_t hash[static 32U]);

#endif /* SHA2_H_ */
