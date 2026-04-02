#ifndef SHA2_H_
#define SHA2_H_

#include <stdint.h>
#include <stddef.h>

/** SHA-224 digest length in bytes. */
#define SHA224_HASH_LEN     28U

/** SHA-256 digest length in bytes. */
#define SHA256_HASH_LEN     32U

/** SHA-384 digest length in bytes. */
#define SHA384_HASH_LEN     48U

/** SHA-512 digest length in bytes. */
#define SHA512_HASH_LEN     64U

/** SHA-512/224 digest length in bytes. */
#define SHA512_224_HASH_LEN 28U

/** SHA-512/256 digest length in bytes. */
#define SHA512_256_HASH_LEN 32U

/** Buffer size needed for a SHA-224 hash string representation. */
#define SHA224_STR_LEN     ((SHA224_HASH_LEN * 2U) + 1U)

/** Buffer size needed for a SHA-256 hash string representation. */
#define SHA256_STR_LEN     ((SHA256_HASH_LEN * 2U) + 1U)

/** Buffer size needed for a SHA-384 hash string representation. */
#define SHA384_STR_LEN     ((SHA384_HASH_LEN * 2U) + 1U)

/** Buffer size needed for a SHA-512 hash string representation. */
#define SHA512_STR_LEN     ((SHA512_HASH_LEN * 2U) + 1U)

/** Buffer size needed for a SHA-512/224 hash string representation. */
#define SHA512_224_STR_LEN ((SHA512_224_HASH_LEN * 2U) + 1U)

/** Buffer size needed for a SHA-512/256 hash string representation. */
#define SHA512_256_STR_LEN ((SHA512_256_HASH_LEN * 2U) + 1U)

/**
 * SHA-224 / SHA-256 hashing context.
 *
 * Stores intermediate state during incremental processing.
 */
typedef struct {
  /** Current position in chunk buffer. */
  size_t chunk_idx;

  /** Total processed message length in bytes. */
  uint64_t msg_len;

  /** Internal hash state. */
  uint32_t h[8U];

  /** Chunk buffer, when this gets filled it will processed and the internal hash state will be updated. */
  uint8_t chunk[64U];
} sha256_ctx;

/**
 * SHA-224 context type.
 *
 * Alias of sha256_ctx because SHA-224 shares the same internal structure.
 */
typedef sha256_ctx sha224_ctx;

/**
 * SHA-384 / SHA-512 / SHA-512/224 / SHA-512/256 hashing context.
 *
 * Stores intermediate state during incremental processing.
 */
typedef struct {
  /** Current position in chunk buffer. */
  size_t chunk_idx;

  /** LSB of total processed message length in bytes. */
  uint64_t msg_len_low;

  /** MSB of total processed message length in bytes. */
  uint64_t msg_len_high;

  /** Internal hash state. */
  uint64_t h[8U];

  /** Chunk buffer, when this gets filled it will processed and the internal hash state will be updated. */
  uint8_t chunk[128U];
} sha512_ctx;

/**
 * SHA-384 context type.
 *
 * Alias of sha512_ctx because SHA-384 shares the same internal structure.
 */
typedef sha512_ctx sha384_ctx;

/**
 * SHA-512/224 context type.
 *
 * Alias of sha512_ctx because SHA-512/224 shares the same internal structure.
 */
typedef sha512_ctx sha512_224_ctx;

/**
 * SHA-512/256 context type.
 *
 * Alias of sha512_ctx because SHA-512/256 shares the same internal structure.
 */
typedef sha512_ctx sha512_256_ctx;

/*************************
 *        SHA224
 ************************/

/**
 * Compute SHA-224 digest for a complete buffer.
 *
 * @param[in]   data    Input data buffer.
 * @param[in]   size    Input size in bytes.
 * @param[out]  result  Output digest buffer, has to be at least SHA224_HASH_LEN in size.
 */
extern void sha224(const uint8_t *data, size_t size, uint8_t result[static SHA224_HASH_LEN]);

/**
 * Initialize a SHA-224 context.
 *
 * This should be called when beginning a new hash calculation using the streaming protocol.
 * Then make one or multiple calls to sha224_process to process data and finally one call to sha224_finalize
 * to compute the final digest.
 *
 * @param[in,out]  ctx  SHA-224 context.
 */
extern void sha224_init(sha224_ctx *ctx);

/**
 * Process data for a SHA-224 context.
 *
 * @param[in,out]  ctx   SHA-224 context.
 * @param[in]      data  Data to process.
 * @param[in]      size  Data length.
 */
extern void sha224_process(sha224_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA-224 computation producing the final digest.
 *
 * This call is destructive, any consecutive calls to the same function will not return the same digest.
 * Also adding more data after a call to this function would not yield the expected result.
 * Call sha224_init to start a new calculation.
 *
 * @param[in,out]  ctx     SHA-224 context.
 * @param[out]     result  Buffer to place the result in, has to be at least SHA224_HASH_LEN in size.
 */
extern void sha224_finalize(sha224_ctx *ctx, uint8_t result[static SHA224_HASH_LEN]);

/**
 * Allocates and creates a string with the hexadecimal representation of the passed SHA-224 hash.
 *
 * This function will call malloc to allocate memory for the string, it's up to the caller to free that memory.
 * If allocation fails, NULL will be returned. To create a string without allocation use sha224_to_str_buffer
 * instead.
 * The resulting string will be in lowercase.
 *
 * @param[in]  hash  The SHA-224 hash to create a string for, has to be at least SHA224_HASH_LEN in size.
 *
 * @return     Resulting string on success, otherwise NULL. Must be freed by the caller.
 */
extern char* sha224_to_str(const uint8_t hash[static SHA224_HASH_LEN]);

/**
 * Creates a string with the hexadecimal representation of the passed SHA-224 hash.
 *
 * The resulting string will be placed in the passed char buffer, no allocations will be made.
 * The resulting string will be in lowercase.
 *
 * @param[in]   hash  The SHA-224 hash to create a string for, has to be at least SHA224_HASH_LEN in size.
 * @param[out]  dst   The destination buffer to place the string, has to be at least SHA224_STR_LEN in size.
 */
extern void sha224_to_str_buffer(const uint8_t hash[static SHA224_HASH_LEN], char dst[static SHA224_STR_LEN]);

/*************************
 *        SHA256
 ************************/

/**
 * Compute SHA-256 digest for a complete buffer.
 *
 * @param[in]   data    Input data buffer.
 * @param[in]   size    Input size in bytes.
 * @param[out]  result  Output digest buffer, has to be at least SHA56_HASH_LEN in size.
 */
extern void sha256(const uint8_t *data, size_t size, uint8_t result[static SHA256_HASH_LEN]);

/**
 * Initialize a SHA-256 context.
 *
 * This should be called when beginning a new hash calculation using the streaming protocol.
 * Then make one or multiple calls to sha256_process to process data and finally one call to sha256_finalize
 * to compute the final digest.
 *
 * @param[in,out]  ctx  SHA-256 context.
 */
extern void sha256_init(sha256_ctx *ctx);

/**
 * Process data for a SHA-256 context.
 *
 * @param[in,out]  ctx   SHA-256 context.
 * @param[in]      data  Data to process.
 * @param[in]      size  Data length.
 */
extern void sha256_process(sha256_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA-256 computation producing the final digest.
 *
 * This call is destructive, any consecutive calls to the same function will not return the same digest.
 * Also adding more data after a call to this function would not yield the expected result.
 * Call sha256_init to start a new calculation.
 *
 * @param[in,out]  ctx     SHA-256 context.
 * @param[out]     result  Buffer to place the result in, has to be at least SHA256_HASH_LEN in size.
 */
extern void sha256_finalize(sha256_ctx *ctx, uint8_t result[static SHA256_HASH_LEN]);

/**
 * Allocates and creates a string with the hexadecimal representation of the passed SHA-256 hash.
 *
 * This function will call malloc to allocate memory for the string, it's up to the caller to free that memory.
 * If allocation fails, NULL will be returned. To create a string without allocation use sha256_to_str_buffer
 * instead.
 * The resulting string will be in lowercase.
 *
 * @param[in]  hash  The SHA-256 hash to create a string for, has to be at least SHA256_HASH_LEN in size.
 *
 * @return     Resulting string on success, otherwise NULL. Must be freed by the caller.
 */
extern char* sha256_to_str(const uint8_t hash[static SHA256_HASH_LEN]);

/**
 * Creates a string with the hexadecimal representation of the passed SHA-256 hash.
 *
 * The resulting string will be placed in the passed char buffer, no allocations will be made.
 * The resulting string will be in lowercase.
 *
 * @param[in]   hash  The SHA-256 hash to create a string for, has to be at least SHA256_HASH_LEN in size.
 * @param[out]  dst   The destination buffer to place the string, has to be at least SHA256_STR_LEN in size.
 */
extern void sha256_to_str_buffer(const uint8_t hash[static SHA256_HASH_LEN], char dst[static SHA256_STR_LEN]);

/*************************
 *        SHA384
 ************************/

/**
 * Compute SHA-384 digest for a complete buffer.
 *
 * @param[in]   data    Input data buffer.
 * @param[in]   size    Input size in bytes.
 * @param[out]  result  Output digest buffer, has to be at least SHA384_HASH_LEN in size.
 */
extern void sha384(const uint8_t *data, size_t size, uint8_t result[static SHA384_HASH_LEN]);

/**
 * Initialize a SHA-384 context.
 *
 * This should be called when beginning a new hash calculation using the streaming protocol.
 * Then make one or multiple calls to sha384_process to process data and finally one call to sha384_finalize
 * to compute the final digest.
 *
 * @param[in,out]  ctx  SHA-384 context.
 */
extern void sha384_init(sha384_ctx *ctx);

/**
 * Process data for a SHA-384 context.
 *
 * @param[in,out]  ctx   SHA-384 context.
 * @param[in]      data  Data to process.
 * @param[in]      size  Data length.
 */
extern void sha384_process(sha384_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA-384 computation producing the final digest.
 *
 * This call is destructive, any consecutive calls to the same function will not return the same digest.
 * Also adding more data after a call to this function would not yield the expected result.
 * Call sha384_init to start a new calculation.
 *
 * @param[in,out]  ctx     SHA-384 context.
 * @param[out]     result  Buffer to place the result in, has to be at least SHA384_HASH_LEN in size.
 */
extern void sha384_finalize(sha384_ctx *ctx, uint8_t result[static SHA384_HASH_LEN]);

/**
 * Allocates and creates a string with the hexadecimal representation of the passed SHA-384 hash.
 *
 * This function will call malloc to allocate memory for the string, it's up to the caller to free that memory.
 * If allocation fails, NULL will be returned. To create a string without allocation use sha384_to_str_buffer
 * instead.
 * The resulting string will be in lowercase.
 *
 * @param[in]  hash  The SHA-384 hash to create a string for, has to be at least SHA384_HASH_LEN in size.
 *
 * @return     Resulting string on success, otherwise NULL. Must be freed by the caller.
 */
extern char* sha384_to_str(const uint8_t hash[static SHA384_HASH_LEN]);

/**
 * Creates a string with the hexadecimal representation of the passed SHA-384 hash.
 *
 * The resulting string will be placed in the passed char buffer, no allocations will be made.
 * The resulting string will be in lowercase.
 *
 * @param[in]   hash  The SHA-384 hash to create a string for, has to be at least SHA384_HASH_LEN in size.
 * @param[out]  dst   The destination buffer to place the string, has to be at least SHA384_STR_LEN in size.
 */
extern void sha384_to_str_buffer(const uint8_t hash[static SHA384_HASH_LEN], char dst[static SHA384_STR_LEN]);

/*************************
 *        SHA512
 ************************/

/**
 * Compute SHA-512 digest for a complete buffer.
 *
 * @param[in]   data    Input data buffer.
 * @param[in]   size    Input size in bytes.
 * @param[out]  result  Output digest buffer, has to be at least SHA512_HASH_LEN in size.
 */
extern void sha512(const uint8_t *data, size_t size, uint8_t result[static SHA512_HASH_LEN]);

/**
 * Initialize a SHA-512 context.
 *
 * This should be called when beginning a new hash calculation using the streaming protocol.
 * Then make one or multiple calls to sha512_process to process data and finally one call to sha512_finalize
 * to compute the final digest.
 *
 * @param[in,out]  ctx  SHA-512 context.
 */
extern void sha512_init(sha512_ctx *ctx);

/**
 * Process data for a SHA-512 context.
 *
 * @param[in,out]  ctx   SHA-512 context.
 * @param[in]      data  Data to process.
 * @param[in]      size  Data length.
 */
extern void sha512_process(sha512_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA-512 computation producing the final digest.
 *
 * This call is destructive, any consecutive calls to the same function will not return the same digest.
 * Also adding more data after a call to this function would not yield the expected result.
 * Call sha512_init to start a new calculation.
 *
 * @param[in,out]  ctx     SHA-512 context.
 * @param[out]     result  Buffer to place the result in, has to be at least SHA512_HASH_LEN in size.
 */
extern void sha512_finalize(sha512_ctx *ctx, uint8_t result[static SHA512_HASH_LEN]);

/**
 * Allocates and creates a string with the hexadecimal representation of the passed SHA-512 hash.
 *
 * This function will call malloc to allocate memory for the string, it's up to the caller to free that memory.
 * If allocation fails, NULL will be returned. To create a string without allocation use sha512_to_str_buffer
 * instead.
 * The resulting string will be in lowercase.
 *
 * @param[in]  hash  The SHA-512 hash to create a string for, has to be at least SHA512_HASH_LEN in size.
 *
 * @return     Resulting string on success, otherwise NULL. Must be freed by the caller.
 */
extern char* sha512_to_str(const uint8_t hash[static SHA512_HASH_LEN]);

/**
 * Creates a string with the hexadecimal representation of the passed SHA-512 hash.
 *
 * The resulting string will be placed in the passed char buffer, no allocations will be made.
 * The resulting string will be in lowercase.
 *
 * @param[in]   hash  The SHA-512 hash to create a string for, has to be at least SHA512_HASH_LEN in size.
 * @param[out]  dst   The destination buffer to place the string, has to be at least SHA512_STR_LEN in size.
 */
extern void sha512_to_str_buffer(const uint8_t hash[static SHA512_HASH_LEN], char dst[static SHA512_STR_LEN]);

/*************************
 *      SHA512/224
 ************************/

/**
 * Compute SHA-512/224 digest for a complete buffer.
 *
 * @param[in]   data    Input data buffer.
 * @param[in]   size    Input size in bytes.
 * @param[out]  result  Output digest buffer, has to be at least SHA512_224_HASH_LEN in size.
 */
extern void sha512_224(const uint8_t *data, size_t size, uint8_t result[static SHA512_224_HASH_LEN]);

/**
 * Initialize a SHA-512/224 context.
 *
 * This should be called when beginning a new hash calculation using the streaming protocol.
 * Then make one or multiple calls to sha512_224_process to process data and finally one call to sha512_224_finalize
 * to compute the final digest.
 *
 * @param[in,out]  ctx  SHA-512/224 context.
 */
extern void sha512_224_init(sha512_224_ctx *ctx);

/**
 * Process data for a SHA-512/224 context.
 *
 * @param[in,out]  ctx   SHA-512/224 context.
 * @param[in]      data  Data to process.
 * @param[in]      size  Data length.
 */
extern void sha512_224_process(sha512_224_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA-512/224 computation producing the final digest.
 *
 * This call is destructive, any consecutive calls to the same function will not return the same digest.
 * Also adding more data after a call to this function would not yield the expected result.
 * Call sha512_224_init to start a new calculation.
 *
 * @param[in,out]  ctx     SHA-512/224 context.
 * @param[out]     result  Buffer to place the result in, has to be at least SHA512_224_HASH_LEN in size.
 */
extern void sha512_224_finalize(sha512_224_ctx *ctx, uint8_t result[static SHA512_224_HASH_LEN]);

/**
 * Allocates and creates a string with the hexadecimal representation of the passed SHA-512/224 hash.
 *
 * This function will call malloc to allocate memory for the string, it's up to the caller to free that memory.
 * If allocation fails, NULL will be returned. To create a string without allocation use sha512_224_to_str_buffer
 * instead.
 * The resulting string will be in lowercase.
 *
 * @param[in]  hash  The SHA-512/224 hash to create a string for, has to be at least SHA512_224_HASH_LEN in size.
 *
 * @return     Resulting string on success, otherwise NULL. Must be freed by the caller.
 */
extern char* sha512_224_to_str(const uint8_t hash[static SHA512_224_HASH_LEN]);

/**
 * Creates a string with the hexadecimal representation of the passed SHA-512/224 hash.
 *
 * The resulting string will be placed in the passed char buffer, no allocations will be made.
 * The resulting string will be in lowercase.
 *
 * @param[in]   hash  The SHA-512/224 hash to create a string for, has to be at least SHA512_224_HASH_LEN in size.
 * @param[out]  dst   The destination buffer to place the string, has to be at least SHA512_224_STR_LEN in size.
 */
extern void sha512_224_to_str_buffer(const uint8_t hash[static SHA512_224_HASH_LEN], char dst[static SHA512_224_STR_LEN]);

/*************************
 *      SHA512/256
 ************************/

/**
 * Compute SHA-512/256 digest for a complete buffer.
 *
 * @param[in]   data    Input data buffer.
 * @param[in]   size    Input size in bytes.
 * @param[out]  result  Output digest buffer, has to be at least SHA512_256_HASH_LEN in size.
 */
extern void sha512_256(const uint8_t *data, size_t size, uint8_t result[static SHA512_256_HASH_LEN]);

/**
 * Initialize a SHA-512/256 context.
 *
 * This should be called when beginning a new hash calculation using the streaming protocol.
 * Then make one or multiple calls to sha512_256_process to process data and finally one call to sha512_256_finalize
 * to compute the final digest.
 *
 * @param[in,out]  ctx  SHA-512/256 context.
 */
extern void sha512_256_init(sha512_256_ctx *ctx);

/**
 * Process data for a SHA-512/256 context.
 *
 * @param[in,out]  ctx   SHA-512/256 context.
 * @param[in]      data  Data to process.
 * @param[in]      size  Data length.
 */
extern void sha512_256_process(sha512_256_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA-512/256 computation producing the final digest.
 *
 * This call is destructive, any consecutive calls to the same function will not return the same digest.
 * Also adding more data after a call to this function would not yield the expected result.
 * Call sha512_256_init to start a new calculation.
 *
 * @param[in,out]  ctx     SHA-512/256 context.
 * @param[out]     result  Buffer to place the result in, has to be at least SHA512_256_HASH_LEN in size.
 */
extern void sha512_256_finalize(sha512_256_ctx *ctx, uint8_t result[static SHA512_256_HASH_LEN]);

/**
 * Allocates and creates a string with the hexadecimal representation of the passed SHA-512/256 hash.
 *
 * This function will call malloc to allocate memory for the string, it's up to the caller to free that memory.
 * If allocation fails, NULL will be returned. To create a string without allocation use sha512_256_to_str_buffer
 * instead.
 * The resulting string will be in lowercase.
 *
 * @param[in]  hash  The SHA-512/256 hash to create a string for, has to be at least SHA512_256_HASH_LEN in size.
 *
 * @return     Resulting string on success, otherwise NULL. Must be freed by the caller.
 */
extern char* sha512_256_to_str(const uint8_t hash[static SHA512_256_HASH_LEN]);

/**
 * Creates a string with the hexadecimal representation of the passed SHA-512/256 hash.
 *
 * The resulting string will be placed in the passed char buffer, no allocations will be made.
 * The resulting string will be in lowercase.
 *
 * @param[in]   hash  The SHA-512/256 hash to create a string for, has to be at least SHA512_256_HASH_LEN in size.
 * @param[out]  dst   The destination buffer to place the string, has to be at least SHA512_256_STR_LEN in size.
 */
extern void sha512_256_to_str_buffer(const uint8_t hash[static SHA512_256_HASH_LEN], char dst[static SHA512_256_STR_LEN]);

#endif /* SHA2_H_ */
