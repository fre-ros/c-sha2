#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "test_util.h"

#define SHAXXX_TEST(test, hash_type, hash_func, to_string_func) do \
  { \
    hash_type hash[8U]; \
    hash_func(test.msg, test.msg_length, hash); \
    char *hash_string = to_string_func(hash); \
    assert(strcmp(hash_string, test.expected_hash) == 0); \
    free(hash_string); \
  } while(0)

#define SHAXXX_INIT_FEED_FINALIZE_TEST(test, ctx_type, hash_type, init_func, feed_func, finalize_func, to_string_func) do \
  { \
    hash_type hash[8U]; \
    ctx_type ctx; \
    init_func(&ctx); \
    feed_func(&ctx, test.msg, test.msg_length); \
    finalize_func(&ctx, hash); \
    char *hash_string = to_string_func(hash); \
    assert(strcmp(hash_string, test.expected_hash) == 0); \
    free(hash_string); \
  } while(0)

#define SHAXXX_SEGMENTED_TEST(test, ctx_type, hash_type, init_func, feed_func, finalize_func, to_string_func) do \
  { \
    hash_type hash[8U]; \
    ctx_type ctx; \
    init_func(&ctx); \
    for (size_t msg_i = 0; msg_i < test.msg_length; msg_i++) \
    { \
      feed_func(&ctx, &test.msg[msg_i], 1); \
    } \
    finalize_func(&ctx, hash); \
    char *hash_string = to_string_func(hash); \
    assert(strcmp(hash_string, test.expected_hash) == 0); \
    free(hash_string); \
  } while(0)

static void run_sha224_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint32_t, sha224, sha224_to_string);
    SHAXXX_INIT_FEED_FINALIZE_TEST(test_data[i], sha224_ctx, uint32_t, sha224_init, sha224_feed, sha224_finalize, sha224_to_string);
    SHAXXX_SEGMENTED_TEST(test_data[i], sha224_ctx, uint32_t, sha224_init, sha224_feed, sha224_finalize, sha224_to_string);
  }
  puts("OK");
}

static void run_sha256_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint32_t, sha256, sha256_to_string);
    SHAXXX_INIT_FEED_FINALIZE_TEST(test_data[i], sha256_ctx, uint32_t, sha256_init, sha256_feed, sha256_finalize, sha256_to_string);
    SHAXXX_SEGMENTED_TEST(test_data[i], sha256_ctx, uint32_t, sha256_init, sha256_feed, sha256_finalize, sha256_to_string);
  }
  puts("OK");
}

int main(void)
{
  size_t number_of_tests;
  struct test_data *sha256_test_data;

  sha256_test_data = load_test_file("test/nist_test_vectors/SHA224ShortMsg.rsp", &number_of_tests);
  run_sha224_tests(sha256_test_data, number_of_tests, "SHA224 short");
  free_test_data(sha256_test_data, number_of_tests);

  sha256_test_data = load_test_file("test/nist_test_vectors/SHA224LongMsg.rsp", &number_of_tests);
  run_sha224_tests(sha256_test_data, number_of_tests, "SHA224 long");
  free_test_data(sha256_test_data, number_of_tests);

  sha256_test_data = load_test_file("test/nist_test_vectors/SHA256ShortMsg.rsp", &number_of_tests);
  run_sha256_tests(sha256_test_data, number_of_tests, "SHA256 short");
  free_test_data(sha256_test_data, number_of_tests);

  sha256_test_data = load_test_file("test/nist_test_vectors/SHA256LongMsg.rsp", &number_of_tests);
  run_sha256_tests(sha256_test_data, number_of_tests, "SHA256 long");
  free_test_data(sha256_test_data, number_of_tests);

  return 0;
}