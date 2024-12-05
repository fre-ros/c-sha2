#ifndef SHA256_H_
#define SHA256_H_

#include <stdint.h>
#include <stddef.h>

/** Context struct for a 256 hash calculation. */
typedef struct {
  size_t msg_len;
  size_t chunk_idx;
  uint32_t h[8U];
  uint8_t chunk[64U];
} sha256_ctx;

typedef sha256_ctx sha224_ctx;

typedef struct {
  size_t msg_len;
  size_t chunk_idx;
  uint64_t h[8U];
  uint8_t chunk[128U];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;
typedef sha512_ctx sha512_224_ctx;

extern void sha224(const uint8_t *data, size_t size, uint32_t result[static 7U]);
extern void sha224_init(sha224_ctx *ctx);
extern void sha224_feed(sha224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha224_finalize(sha224_ctx *ctx, uint32_t result[static 7U]);
extern char* sha224_to_string(const uint32_t hash[static 7U]);

/**
 * Calculate SHA256.
 *
 * For calculation in chunks use sha256_init, sha256_feed and sha256_finalize instead.
 *
 * @param[in]  data    Data to calculate hash for
 * @param[in]  size    Size of the data
 * @param[out] result  Hash result out array
 */
extern void sha256(const uint8_t *data, size_t size, uint32_t result[static 8U]);

/**
 * Initialize a SHA256 calculation context.
 *
 * @param[in] ctx  The hash context
 */
extern void sha256_init(sha256_ctx *ctx);

/**
 * Feed data to the SHA256 calculation.
 *
 * @param[in]  ctx   The hash context
 * @param[in]  data  Data to feed
 * @param[in]  size  Size of the data
 */
extern void sha256_feed(sha256_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA256 calculation.
 *
 * sha256_init has to be called again to start a new calculation.
 *
 * @param[in]   ctx     The hash context
 * @param[out]  result  Hash result out array
 */
extern void sha256_finalize(sha256_ctx *ctx, uint32_t result[static 8U]);

/**
 * Create a hex string representation of the hash.
 *
 * The returned string has to be freed by the caller.
 *
 * @param[in]  hash  Hash to create string from
 *
 * @return     String representation of the hash or NULL if the allocation failed.
 */
extern char* sha256_to_string(const uint32_t hash[static 8U]);

extern void sha384(const uint8_t *data, size_t size, uint64_t result[static 6U]);
extern void sha384_init(sha384_ctx *ctx);
extern void sha384_feed(sha384_ctx *ctx, const uint8_t *data, size_t size);
extern void sha384_finalize(sha384_ctx *ctx, uint64_t result[static 6U]);
extern char* sha384_to_string(const uint64_t hash[static 6U]);

extern void sha512(const uint8_t *data, size_t size, uint64_t result[static 8U]);
extern void sha512_init(sha512_ctx *ctx);
extern void sha512_feed(sha512_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_finalize(sha512_ctx *ctx, uint64_t result[static 8U]);
extern char* sha512_to_string(const uint64_t hash[static 8U]);

extern void sha512_224(const uint8_t *data, size_t size, uint32_t result[static 7U]);
extern void sha512_224_init(sha512_224_ctx *ctx);
extern void sha512_224_feed(sha512_224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_224_finalize(sha512_224_ctx *ctx, uint32_t result[static 7U]);
extern char* sha512_224_to_string(const uint32_t hash[static 7U]);

#endif /* SHA256_H_ */
