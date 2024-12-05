#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"
#include "test_util.h"

#define SHAXXX_TEST(test, hash_type, hash_func, to_string_func) do \
  { \
    hash_type hash[8U]; \
    hash_func(test.msg, test.msg_length, hash); \
    char *hash_string = to_string_func(hash); \
    assert(strcmp(hash_string, test.expected_hash) == 0); \
    free(hash_string); \
  } while(0)

#define SHAXXX_STREAMING_ONE_CALL_TEST(test, ctx_type, hash_type, init_func, feed_func, finalize_func, to_string_func) do \
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

#define SHAXXX_STREAMING_TEST(test, ctx_type, hash_type, init_func, feed_func, finalize_func, to_string_func) do \
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
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint32_t, sha224, sha224_to_string);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha224_ctx, uint32_t, sha224_init, sha224_feed, sha224_finalize, sha224_to_string);
    SHAXXX_STREAMING_TEST(test_data[i], sha224_ctx, uint32_t, sha224_init, sha224_feed, sha224_finalize, sha224_to_string);
  }
  puts("OK");
}

static void run_sha256_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint32_t, sha256, sha256_to_string);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha256_ctx, uint32_t, sha256_init, sha256_feed, sha256_finalize, sha256_to_string);
    SHAXXX_STREAMING_TEST(test_data[i], sha256_ctx, uint32_t, sha256_init, sha256_feed, sha256_finalize, sha256_to_string);
  }
  puts("OK");
}

static void run_sha384_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint64_t, sha384, sha384_to_string);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha384_ctx, uint64_t, sha384_init, sha384_feed, sha384_finalize, sha384_to_string);
    SHAXXX_STREAMING_TEST(test_data[i], sha384_ctx, uint64_t, sha384_init, sha384_feed, sha384_finalize, sha384_to_string);
  }
  puts("OK");
}

static void run_sha512_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint64_t, sha512, sha512_to_string);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha512_ctx, uint64_t, sha512_init, sha512_feed, sha512_finalize, sha512_to_string);
    SHAXXX_STREAMING_TEST(test_data[i], sha512_ctx, uint64_t, sha512_init, sha512_feed, sha512_finalize, sha512_to_string);
  }
  puts("OK");
}

static void run_sha512_224_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint32_t, sha512_224, sha512_224_to_string);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha512_224_ctx, uint32_t, sha512_224_init, sha512_224_feed, sha512_224_finalize, sha512_224_to_string);
    SHAXXX_STREAMING_TEST(test_data[i], sha512_224_ctx, uint32_t, sha512_224_init, sha512_224_feed, sha512_224_finalize, sha512_224_to_string);
  }
  puts("OK");
}

static void run_sha512_256_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint32_t, sha512_256, sha512_256_to_string);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha512_256_ctx, uint32_t, sha512_256_init, sha512_256_feed, sha512_256_finalize, sha512_256_to_string);
    SHAXXX_STREAMING_TEST(test_data[i], sha512_256_ctx, uint32_t, sha512_256_init, sha512_256_feed, sha512_256_finalize, sha512_256_to_string);
  }
  puts("OK");
}

int main(void)
{
  size_t number_of_tests;
  struct test_data *test_data;

  test_data = load_test_file("test/nist_test_vectors/SHA224ShortMsg.rsp", &number_of_tests);
  run_sha224_tests(test_data, number_of_tests, "SHA224 short");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA224LongMsg.rsp", &number_of_tests);
  run_sha224_tests(test_data, number_of_tests, "SHA224 long.");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA256ShortMsg.rsp", &number_of_tests);
  run_sha256_tests(test_data, number_of_tests, "SHA256 short");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA256LongMsg.rsp", &number_of_tests);
  run_sha256_tests(test_data, number_of_tests, "SHA256 long.");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA384ShortMsg.rsp", &number_of_tests);
  run_sha384_tests(test_data, number_of_tests, "SHA384 short");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA384LongMsg.rsp", &number_of_tests);
  run_sha384_tests(test_data, number_of_tests, "SHA384 long.");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA512ShortMsg.rsp", &number_of_tests);
  run_sha512_tests(test_data, number_of_tests, "SHA512 short");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA512LongMsg.rsp", &number_of_tests);
  run_sha512_tests(test_data, number_of_tests, "SHA512 long.");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA512_224ShortMsg.rsp", &number_of_tests);
  run_sha512_224_tests(test_data, number_of_tests, "SHA512/224 short");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA512_224LongMsg.rsp", &number_of_tests);
  run_sha512_224_tests(test_data, number_of_tests, "SHA512/224 long.");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA512_256ShortMsg.rsp", &number_of_tests);
  run_sha512_256_tests(test_data, number_of_tests, "SHA512/256 short");
  free_test_data(test_data, number_of_tests);

  test_data = load_test_file("test/nist_test_vectors/SHA512_256LongMsg.rsp", &number_of_tests);
  run_sha512_256_tests(test_data, number_of_tests, "SHA512/256 long.");
  free_test_data(test_data, number_of_tests);

  return 0;
}
