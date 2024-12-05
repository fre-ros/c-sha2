# c-sha256

SHA256 library for C

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
```c
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
extern void sha256_init(struct sha256_ctx *ctx);

/**
 * Feed data to the SHA256 calculation.
 *
 * @param[in]  ctx   The hash context
 * @param[in]  data  Data to feed
 * @param[in]  size  Size of the data
 */
extern void sha256_feed(struct sha256_ctx *ctx, const uint8_t *data, size_t size);

/**
 * Finalize the SHA256 calculation.
 *
 * sha256_init has to be called again to start a new calculation.
 *
 * @param[in]   ctx     The hash context
 * @param[out]  result  Hash result out array
 */
extern void sha256_finalize(struct sha256_ctx *ctx, uint32_t result[static 8U]);

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
```

## Test
The tests are run by calling make.
<br>The implementation and test files are analyzed with [cppcheck](https://github.com/danmar/cppcheck) before compiling.

```shell
$ make
SHA256 short...OK
SHA256 long...OK
```
To skip [cppcheck](https://github.com/danmar/cppcheck) pass CPPCHECK=0 to make
```shell
$ make CPPCHECK=0
SHA256 short...OK
SHA256 long...OK
```
