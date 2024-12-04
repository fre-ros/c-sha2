#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "test_util.h"

static void sha256_test(const struct test_data *test)
{
  uint32_t hash[8U];
  sha256(test->msg, test->msg_length, hash);

  char *hash_string = sha256_to_string(hash);
  assert(strcmp(hash_string, test->expected_hash) == 0);

  free(hash_string);
}

static void init_feed_finalize_test(const struct test_data *test)
{
  uint32_t hash[8U];

  struct sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_feed(&ctx, test->msg, test->msg_length);
  sha256_finalize(&ctx, hash);

  char *hash_string = sha256_to_string(hash);
  assert(strcmp(hash_string, test->expected_hash) == 0);

  free(hash_string);
}

static void init_feed_finalize_chunked_test(const struct test_data *test)
{
  uint32_t hash[8U];

  struct sha256_ctx ctx;
  sha256_init(&ctx);

  for (size_t i = 0U; i< test->msg_length; i++)
  {
    sha256_feed(&ctx, &test->msg[i], 1);
  }

  sha256_finalize(&ctx, hash);

  char *hash_string = sha256_to_string(hash);
  assert(strcmp(hash_string, test->expected_hash) == 0);
  free(hash_string);
}

static void run_sha256_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    sha256_test(&test_data[i]);
    init_feed_finalize_test(&test_data[i]);
    init_feed_finalize_chunked_test(&test_data[i]);
  }
  puts("OK");
}

int main(void)
{
  size_t number_of_tests;
  struct test_data *sha256_test_data;

  sha256_test_data = load_test_file("test/nist_test_vectors/SHA256ShortMsg.rsp", &number_of_tests);
  run_sha256_tests(sha256_test_data, number_of_tests, "SHA256 short");
  free_test_data(sha256_test_data, number_of_tests);

  sha256_test_data = load_test_file("test/nist_test_vectors/SHA256LongMsg.rsp", &number_of_tests);
  run_sha256_tests(sha256_test_data, number_of_tests, "SHA256 long");
  free_test_data(sha256_test_data, number_of_tests);
}
