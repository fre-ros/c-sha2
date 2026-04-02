# c-sha2

[SHA2](https://en.wikipedia.org/wiki/SHA-2) library for C

- Supports **SHA224**, **SHA256**, **SHA384**, **SHA512**, **SHA512/224** and **SHA512/256**
- Supports one call calculation and streaming protocol
- Requires C standard C99 or newer
- Implementation verified against [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors
- Allocation free implementation (Except for optional **xxx_to_str** functions)

## Usage
To use the library add `sha2.h` and `sha2.c` to your project.
<br>**Example:**
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sha2.h"

static void print_hash(const uint8_t hash[SHA256_HASH_LEN])
{
  char *hash_str = sha256_to_str(hash);
  if (hash_str != NULL)
  {
    puts(hash_str);
    free(hash_str);
  }
}

static void print_hash_without_allocation(const uint8_t hash[SHA256_HASH_LEN])
{
  char hash_str[SHA256_STR_LEN];
  sha256_to_str_buffer(hash, hash_str);
  puts(hash_str);
}

int main(void)
{
  uint8_t hash[SHA256_HASH_LEN];

  // Calculate hash in one call
  const char *msg = "The quick brown fox jumps over the lazy dog.";
  sha256((const uint8_t*)msg, strlen(msg), hash);
  print_hash(hash);

  // Calculate hash with streaming protocol
  const char *msg_part_one = "The quick brown fox ";
  const char *msg_part_two = "jumps over the lazy dog.";

  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_process(&ctx, (const uint8_t*)msg_part_one, strlen(msg_part_one));
  sha256_process(&ctx, (const uint8_t*)msg_part_two, strlen(msg_part_two));
  sha256_finalize(&ctx, hash);
  print_hash_without_allocation(hash);

  return 0;
}

// Output:
//  ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c
//  ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c
```

## API
The strings returned from **xxx_to_str** functions must be freed by the caller.
<br>Use **xxx_to_str_buffer** to create a string without allocation.
```c
/*************************
 *        SHA224
 ************************/

/**
 * @brief Compute SHA-224 digest for a complete buffer.
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
 * @return     Resulting string on success, otherwise NULL.
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
 * @brief Compute SHA-256 digest for a complete buffer.
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
 * @return     Resulting string on success, otherwise NULL.
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
 * @brief Compute SHA-384 digest for a complete buffer.
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
 * @return     Resulting string on success, otherwise NULL.
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
 * @brief Compute SHA-512 digest for a complete buffer.
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
 * @return     Resulting string on success, otherwise NULL.
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
 * @brief Compute SHA-512/224 digest for a complete buffer.
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
 * @return     Resulting string on success, otherwise NULL.
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
 * @brief Compute SHA-512/256 digest for a complete buffer.
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
 * @return     Resulting string on success, otherwise NULL.
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

```

## Test
The test checks all [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors against the implementation.
The tests can be run by calling make.

```shell
$ make
SHA224 short.......OK
SHA224 long........OK
SHA256 short.......OK
SHA256 long........OK
SHA384 short.......OK
SHA384 long........OK
SHA512 short.......OK
SHA512 long........OK
SHA512/224 short...OK
SHA512/224 long....OK
SHA512/256 short...OK
SHA512/256 long....OK
```
