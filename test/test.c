#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"
#include "test_util.h"

static char hash_string[SHA512_STR_LEN];

#define SHAXXX_TEST(test, hash_type, hash_func, to_str_func) do \
  { \
    hash_type hash[SHA512_HASH_LEN]; \
    hash_func(test.msg, test.msg_length, hash); \
    to_str_func(hash, hash_string); \
    assert(strcmp(hash_string, test.expected_hash) == 0); \
  } while(0)

#define SHAXXX_STREAMING_ONE_CALL_TEST(test, ctx_type, hash_type, init_func, process_func, finalize_func, to_str_func) do \
  { \
    hash_type hash[SHA512_HASH_LEN]; \
    ctx_type ctx; \
    init_func(&ctx); \
    process_func(&ctx, test.msg, test.msg_length); \
    finalize_func(&ctx, hash); \
    to_str_func(hash, hash_string); \
    assert(strcmp(hash_string, test.expected_hash) == 0); \
  } while(0)

#define SHAXXX_STREAMING_TEST(test, ctx_type, hash_type, init_func, process_func, finalize_func, to_str_func) do \
  { \
    hash_type hash[SHA512_HASH_LEN]; \
    ctx_type ctx; \
    init_func(&ctx); \
    for (size_t msg_i = 0; msg_i < test.msg_length; msg_i++) \
    { \
      process_func(&ctx, &test.msg[msg_i], 1); \
    } \
    finalize_func(&ctx, hash); \
    to_str_func(hash, hash_string); \
    assert(strcmp(hash_string, test.expected_hash) == 0); \
  } while(0)

static void run_sha224_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint8_t, sha224, sha224_to_str_buffer);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha224_ctx, uint8_t, sha224_init, sha224_process, sha224_finalize, sha224_to_str_buffer);
    SHAXXX_STREAMING_TEST(test_data[i], sha224_ctx, uint8_t, sha224_init, sha224_process, sha224_finalize, sha224_to_str_buffer);
  }
  puts("OK");
}

static void run_sha256_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint8_t, sha256, sha256_to_str_buffer);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha256_ctx, uint8_t, sha256_init, sha256_process, sha256_finalize, sha256_to_str_buffer);
    SHAXXX_STREAMING_TEST(test_data[i], sha256_ctx, uint8_t, sha256_init, sha256_process, sha256_finalize, sha256_to_str_buffer);
  }
  puts("OK");
}

static void run_sha384_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint8_t, sha384, sha384_to_str_buffer);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha384_ctx, uint8_t, sha384_init, sha384_process, sha384_finalize, sha384_to_str_buffer);
    SHAXXX_STREAMING_TEST(test_data[i], sha384_ctx, uint8_t, sha384_init, sha384_process, sha384_finalize, sha384_to_str_buffer);
  }
  puts("OK");
}

static void run_sha512_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s.......", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint8_t, sha512, sha512_to_str_buffer);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha512_ctx, uint8_t, sha512_init, sha512_process, sha512_finalize, sha512_to_str_buffer);
    SHAXXX_STREAMING_TEST(test_data[i], sha512_ctx, uint8_t, sha512_init, sha512_process, sha512_finalize, sha512_to_str_buffer);
  }
  puts("OK");
}

static void run_sha512_224_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint8_t, sha512_224, sha512_224_to_str_buffer);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha512_224_ctx, uint8_t, sha512_224_init, sha512_224_process, sha512_224_finalize, sha512_224_to_str_buffer);
    SHAXXX_STREAMING_TEST(test_data[i], sha512_224_ctx, uint8_t, sha512_224_init, sha512_224_process, sha512_224_finalize, sha512_224_to_str_buffer);
  }
  puts("OK");
}

static void run_sha512_256_tests(struct test_data *test_data, size_t number_of_tests, const char *test_name)
{
  printf("%s...", test_name);
  for (size_t i = 0; i < number_of_tests; i++)
  {
    SHAXXX_TEST(test_data[i], uint8_t, sha512_256, sha512_256_to_str_buffer);
    SHAXXX_STREAMING_ONE_CALL_TEST(test_data[i], sha512_256_ctx, uint8_t, sha512_256_init, sha512_256_process, sha512_256_finalize, sha512_256_to_str_buffer);
    SHAXXX_STREAMING_TEST(test_data[i], sha512_256_ctx, uint8_t, sha512_256_init, sha512_256_process, sha512_256_finalize, sha512_256_to_str_buffer);
  }
  puts("OK");
}

int main(void)
{
  size_t number_of_tests;
  struct test_data *test_data;

  setbuf(stdout, NULL);

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
