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

#endif /* SHA256_H_ */
