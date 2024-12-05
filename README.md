# c-sha2

[SHA2](https://en.wikipedia.org/wiki/SHA-2) library for C

- Supports SHA224, SHA256, SHA384, SHA512, SHA512/224 and SHA512/256
- Supports direct calculation and streaming protocol
- Requires C99 or newer
- Implementation verified against [NIST CAVP](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Secure-Hashing) test vectors

## Usage
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sha256.h"

static void print_hash(const uint32_t hash[8])
{
  char *hash_str = sha256_to_string(hash);
  if (hash_str != NULL)
  {
    puts(hash_str);
    free(hash_str);
  }
}

int main(void)
{
  const char *msg = "The quick brown fox jumps over the lazy dog.";

  uint32_t hash[8];

  // Calculate hash in one call
  sha256((uint8_t*)msg, strlen(msg), hash);
  print_hash(hash);

  // Calculate hash in chunks
  const char *msg_part_one = "The quick brown fox ";
  const char *msg_part_two = "jumps over the lazy dog.";

  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_feed(&ctx, (uint8_t*)msg_part_one, strlen(msg_part_one));
  sha256_feed(&ctx, (uint8_t*)msg_part_two, strlen(msg_part_two));
  sha256_finalize(&ctx, hash);
  print_hash(hash);

  return 0;
}
```

Output:
```
ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c
ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c
```
## API
The strings returned from xxx_to_string functions has to be freed by the caller.
```c
/*************************
 *        SHA224
 ************************/
extern void sha224(const uint8_t *data, size_t size, uint32_t result[static 7U]);
extern void sha224_init(sha224_ctx *ctx);
extern void sha224_feed(sha224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha224_finalize(sha224_ctx *ctx, uint32_t result[static 7U]);
extern char* sha224_to_string(const uint32_t hash[static 7U]);

/*************************
 *        SHA256
 ************************/
extern void sha256(const uint8_t *data, size_t size, uint32_t result[static 8U]);
extern void sha256_init(sha256_ctx *ctx);
extern void sha256_feed(sha256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha256_finalize(sha256_ctx *ctx, uint32_t result[static 8U]);
extern char* sha256_to_string(const uint32_t hash[static 8U]);

/*************************
 *        SHA384
 ************************/
extern void sha384(const uint8_t *data, size_t size, uint64_t result[static 6U]);
extern void sha384_init(sha384_ctx *ctx);
extern void sha384_feed(sha384_ctx *ctx, const uint8_t *data, size_t size);
extern void sha384_finalize(sha384_ctx *ctx, uint64_t result[static 6U]);
extern char* sha384_to_string(const uint64_t hash[static 6U]);

/*************************
 *        SHA512
 ************************/
extern void sha512(const uint8_t *data, size_t size, uint64_t result[static 8U]);
extern void sha512_init(sha512_ctx *ctx);
extern void sha512_feed(sha512_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_finalize(sha512_ctx *ctx, uint64_t result[static 8U]);
extern char* sha512_to_string(const uint64_t hash[static 8U]);

/*************************
 *        SHA512/224
 ************************/
extern void sha512_224(const uint8_t *data, size_t size, uint32_t result[static 7U]);
extern void sha512_224_init(sha512_224_ctx *ctx);
extern void sha512_224_feed(sha512_224_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_224_finalize(sha512_224_ctx *ctx, uint32_t result[static 7U]);
extern char* sha512_224_to_string(const uint32_t hash[static 7U]);

/*************************
 *        SHA512/256
 ************************/
extern void sha512_256(const uint8_t *data, size_t size, uint32_t result[static 8U]);
extern void sha512_256_init(sha512_256_ctx *ctx);
extern void sha512_256_feed(sha512_256_ctx *ctx, const uint8_t *data, size_t size);
extern void sha512_256_finalize(sha512_256_ctx *ctx, uint32_t result[static 8U]);
extern char* sha512_256_to_string(const uint32_t hash[static 8U]);
```

## Test
The tests are run by calling make.
<br>The implementation and test files are analyzed with [cppcheck](https://github.com/danmar/cppcheck) before compiling.
<br>To skip [cppcheck](https://github.com/danmar/cppcheck) pass CPPCHECK=0 to make

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
