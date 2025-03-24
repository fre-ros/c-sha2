# c-sha2

[SHA2](https://en.wikipedia.org/wiki/SHA-2) library for C

- Supports **SHA224**, **SHA256**, **SHA384**, **SHA512**, **SHA512/224** and **SHA512/256**
- Supports one call calculation and streaming protocol
- Requires C99 or newer
- Implementation verified against [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors

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
  const char *msg = "The quick brown fox jumps over the lazy dog.";

  uint8_t hash[SHA256_HASH_LEN];

  // Calculate hash in one call
  sha256((uint8_t*)msg, strlen(msg), hash);
  print_hash(hash);

  // Calculate hash with streaming protocol
  const char *msg_part_one = "The quick brown fox ";
  const char *msg_part_two = "jumps over the lazy dog.";

  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_process(&ctx, (uint8_t*)msg_part_one, strlen(msg_part_one));
  sha256_process(&ctx, (uint8_t*)msg_part_two, strlen(msg_part_two));
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
extern void sha224(const uint8_t *data, size_t size, uint8_t result[SHA224_HASH_LEN]);
extern void sha224_init(sha224_ctx *ctx);
extern void sha224_process(sha224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha224_finalize(sha224_ctx *ctx, uint8_t result[SHA224_HASH_LEN]);
extern char* sha224_to_str(const uint8_t hash[SHA224_HASH_LEN]);
extern void sha224_to_str_buffer(const uint8_t hash[SHA224_HASH_LEN], char dst[SHA224_STR_LEN]);

/*************************
 *        SHA256
 ************************/
extern void sha256(const uint8_t *data, size_t size, uint8_t result[static SHA256_HASH_LEN]);
extern void sha256_init(sha256_ctx *ctx);
extern void sha256_process(sha256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha256_finalize(sha256_ctx *ctx, uint8_t result[static SHA256_HASH_LEN]);
extern char* sha256_to_str(const uint8_t hash[static SHA256_HASH_LEN]);
extern void sha256_to_str_buffer(const uint8_t hash[static SHA256_HASH_LEN], char dst[SHA256_STR_LEN]);

/*************************
 *        SHA384
 ************************/
extern void sha384(const uint8_t *data, size_t size, uint8_t result[static SHA384_HASH_LEN]);
extern void sha384_init(sha384_ctx *ctx);
extern void sha384_process(sha384_ctx *ctx, const uint8_t *data, size_t size);
extern void sha384_finalize(sha384_ctx *ctx, uint8_t result[static SHA384_HASH_LEN]);
extern char* sha384_to_str(const uint8_t hash[static SHA384_HASH_LEN]);
extern void sha384_to_str_buffer(const uint8_t hash[static SHA384_HASH_LEN], char dst[SHA384_STR_LEN]);

/*************************
 *        SHA512
 ************************/
extern void sha512(const uint8_t *data, size_t size, uint8_t result[static SHA512_HASH_LEN]);
extern void sha512_init(sha512_ctx *ctx);
extern void sha512_process(sha512_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_finalize(sha512_ctx *ctx, uint8_t result[static SHA512_HASH_LEN]);
extern char* sha512_to_str(const uint8_t hash[static SHA512_HASH_LEN]);
extern void sha512_to_str_buffer(const uint8_t hash[static SHA512_HASH_LEN], char dst[SHA512_STR_LEN]);

/*************************
 *      SHA512/224
 ************************/
extern void sha512_224(const uint8_t *data, size_t size, uint8_t result[static SHA512_224_HASH_LEN]);
extern void sha512_224_init(sha512_224_ctx *ctx);
extern void sha512_224_process(sha512_224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_224_finalize(sha512_224_ctx *ctx, uint8_t result[static SHA512_224_HASH_LEN]);
extern char* sha512_224_to_str(const uint8_t hash[static SHA512_224_HASH_LEN]);
extern void sha512_224_to_str_buffer(const uint8_t hash[static SHA512_224_HASH_LEN], char dst[SHA512_224_STR_LEN]);

/*************************
 *      SHA512/256
 ************************/
extern void sha512_256(const uint8_t *data, size_t size, uint8_t result[static SHA512_256_HASH_LEN]);
extern void sha512_256_init(sha512_256_ctx *ctx);
extern void sha512_256_process(sha512_256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_256_finalize(sha512_256_ctx *ctx, uint8_t result[static SHA512_256_HASH_LEN]);
extern char* sha512_256_to_str(const uint8_t hash[static SHA512_256_HASH_LEN]);
extern void sha512_256_to_str_buffer(const uint8_t hash[static SHA512_256_HASH_LEN], char dst[SHA512_256_STR_LEN]);
```

## Test
The tests are run by calling make.

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
