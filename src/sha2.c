#include "sha2.h"

#include <string.h>
#include <stdlib.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define RROTATE32(n, r) (((n) << (32U - (r))) | ((n) >> (r)))
#define RROTATE64(n, r) (((n) << (64U - (r))) | ((n) >> (r)))

#define UNPACK_U32_BE(arr, i) (  \
  ((uint32_t)arr[i]    << 24U) | \
  ((uint32_t)arr[i+1U] << 16U) | \
  ((uint32_t)arr[i+2U] << 8U)  | \
  ((uint32_t)arr[i+3U] << 0U))

#define PACK_U32_BE(arr, i, u32) do \
  { \
    (arr)[(i)+0U] = ((u32) >> 24U) & 0xFFU; \
    (arr)[(i)+1U] = ((u32) >> 16U) & 0xFFU; \
    (arr)[(i)+2U] = ((u32) >> 8U)  & 0xFFU; \
    (arr)[(i)+3U] = ((u32) >> 0U)  & 0xFFU; \
  } while (0)

#define UNPACK_U64_BE(arr, i) (  \
  ((uint64_t)arr[i]    << 56U) | \
  ((uint64_t)arr[i+1U] << 48U) | \
  ((uint64_t)arr[i+2U] << 40U) | \
  ((uint64_t)arr[i+3U] << 32U) | \
  ((uint64_t)arr[i+4U] << 24U) | \
  ((uint64_t)arr[i+5U] << 16U) | \
  ((uint64_t)arr[i+6U] << 8U)  | \
  ((uint64_t)arr[i+7U] << 0U))

#define PACK_U64_BE(arr, i, u64) do \
  { \
    (arr)[(i)+0U] = ((u64) >> 56U) & 0xFFU; \
    (arr)[(i)+1U] = ((u64) >> 48U) & 0xFFU; \
    (arr)[(i)+2U] = ((u64) >> 40U) & 0xFFU; \
    (arr)[(i)+3U] = ((u64) >> 32U) & 0xFFU; \
    (arr)[(i)+4U] = ((u64) >> 24U) & 0xFFU; \
    (arr)[(i)+5U] = ((u64) >> 16U) & 0xFFU; \
    (arr)[(i)+6U] = ((u64) >> 8U)  & 0xFFU; \
    (arr)[(i)+7U] = ((u64) >> 0U)  & 0xFFU; \
  } while (0)

static const uint8_t zero_padding[128U] = {0U};

static const uint32_t k2xx[64U] = {
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
  0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
  0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
  0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
  0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
  0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
  0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
  0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
  0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
  0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
  0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
  0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
  0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
  0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static const uint64_t k5xx[80U] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
  0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha2xx_process(sha256_ctx *ctx)
{
  uint32_t w[64U] =
  {
    [0U]  = UNPACK_U32_BE(ctx->chunk, 0U),
    [1U]  = UNPACK_U32_BE(ctx->chunk, 4U),
    [2U]  = UNPACK_U32_BE(ctx->chunk, 8U),
    [3U]  = UNPACK_U32_BE(ctx->chunk, 12U),
    [4U]  = UNPACK_U32_BE(ctx->chunk, 16U),
    [5U]  = UNPACK_U32_BE(ctx->chunk, 20U),
    [6U]  = UNPACK_U32_BE(ctx->chunk, 24U),
    [7U]  = UNPACK_U32_BE(ctx->chunk, 28U),
    [8U]  = UNPACK_U32_BE(ctx->chunk, 32U),
    [9U]  = UNPACK_U32_BE(ctx->chunk, 36U),
    [10U] = UNPACK_U32_BE(ctx->chunk, 40U),
    [11U] = UNPACK_U32_BE(ctx->chunk, 44U),
    [12U] = UNPACK_U32_BE(ctx->chunk, 48U),
    [13U] = UNPACK_U32_BE(ctx->chunk, 52U),
    [14U] = UNPACK_U32_BE(ctx->chunk, 56U),
    [15U] = UNPACK_U32_BE(ctx->chunk, 60U)
  };

  for (size_t i = 16U; i < 64U; i++)
  {
    uint32_t s0 = RROTATE32(w[i-15U], 7U) ^ RROTATE32(w[i-15U], 18U) ^ (w[i-15U] >> 3U);
    uint32_t s1 = RROTATE32(w[i-2U], 17U) ^ RROTATE32(w[i-2U], 19U)  ^ (w[i-2U] >> 10U);
    w[i]        = w[i-16U] + s0 + w[i-7U] + s1;
  }

  uint32_t a = ctx->h[0U];
  uint32_t b = ctx->h[1U];
  uint32_t c = ctx->h[2U];
  uint32_t d = ctx->h[3U];
  uint32_t e = ctx->h[4U];
  uint32_t f = ctx->h[5U];
  uint32_t g = ctx->h[6U];
  uint32_t h = ctx->h[7U];

  for (size_t i = 0U; i < 64U; i++)
  {
    uint32_t S1     = RROTATE32(e, 6U) ^ RROTATE32(e, 11U) ^ RROTATE32(e, 25U);
    uint32_t ch     = (e & f) ^ ((~e) & g);
    uint32_t temp1  = h + S1 + ch + k2xx[i] + w[i];
    uint32_t S0     = RROTATE32(a, 2U) ^ RROTATE32(a, 13U) ^ RROTATE32(a, 22U);
    uint32_t maj    = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2  = (S0 + maj);

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->h[0U] += a;
  ctx->h[1U] += b;
  ctx->h[2U] += c;
  ctx->h[3U] += d;
  ctx->h[4U] += e;
  ctx->h[5U] += f;
  ctx->h[6U] += g;
  ctx->h[7U] += h;

  ctx->chunk_idx = 0U;
}

static void sha5xx_process(sha512_ctx *ctx)
{
  uint64_t w[80U] =
  {
    [0U]  = UNPACK_U64_BE(ctx->chunk, 0U),
    [1U]  = UNPACK_U64_BE(ctx->chunk, 8U),
    [2U]  = UNPACK_U64_BE(ctx->chunk, 16U),
    [3U]  = UNPACK_U64_BE(ctx->chunk, 24U),
    [4U]  = UNPACK_U64_BE(ctx->chunk, 32U),
    [5U]  = UNPACK_U64_BE(ctx->chunk, 40U),
    [6U]  = UNPACK_U64_BE(ctx->chunk, 48U),
    [7U]  = UNPACK_U64_BE(ctx->chunk, 56U),
    [8U]  = UNPACK_U64_BE(ctx->chunk, 64U),
    [9U]  = UNPACK_U64_BE(ctx->chunk, 72U),
    [10U] = UNPACK_U64_BE(ctx->chunk, 80U),
    [11U] = UNPACK_U64_BE(ctx->chunk, 88U),
    [12U] = UNPACK_U64_BE(ctx->chunk, 96U),
    [13U] = UNPACK_U64_BE(ctx->chunk, 104U),
    [14U] = UNPACK_U64_BE(ctx->chunk, 112U),
    [15U] = UNPACK_U64_BE(ctx->chunk, 120U)
  };

  for (size_t i = 16U; i < 80U; i++)
  {
    uint64_t s0 = RROTATE64(w[i-15U], 1U) ^ RROTATE64(w[i-15U], 8U) ^ (w[i-15U] >> 7U);
    uint64_t s1 = RROTATE64(w[i-2U], 19U) ^ RROTATE64(w[i-2U], 61U) ^ (w[i-2U] >> 6U);
    w[i]        = w[i-16U] + s0 + w[i-7U] + s1;
  }

  uint64_t a = ctx->h[0U];
  uint64_t b = ctx->h[1U];
  uint64_t c = ctx->h[2U];
  uint64_t d = ctx->h[3U];
  uint64_t e = ctx->h[4U];
  uint64_t f = ctx->h[5U];
  uint64_t g = ctx->h[6U];
  uint64_t h = ctx->h[7U];

  for (size_t i = 0U; i < 80U; i++)
  {
    uint64_t S1     = RROTATE64(e, 14U) ^ RROTATE64(e, 18U) ^ RROTATE64(e, 41U);
    uint64_t ch     = (e & f) ^ ((~e) & g);
    uint64_t temp1  = h + S1 + ch + k5xx[i] + w[i];
    uint64_t S0     = RROTATE64(a, 28U) ^ RROTATE64(a, 34U) ^ RROTATE64(a, 39U);
    uint64_t maj    = (a & b) ^ (a & c) ^ (b & c);
    uint64_t temp2  = (S0 + maj);

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->h[0U] += a;
  ctx->h[1U] += b;
  ctx->h[2U] += c;
  ctx->h[3U] += d;
  ctx->h[4U] += e;
  ctx->h[5U] += f;
  ctx->h[6U] += g;
  ctx->h[7U] += h;

  ctx->chunk_idx = 0U;
}

static char nibble_to_hex_char(uint8_t nibble)
{
  return "0123456789abcdef"[nibble & 0xFU];
}

static char* hash_to_string(const uint8_t *hash, size_t size)
{
  size_t str_index = 0U;

  /* 2 hex characters for every uint8_t and NULL terminator. */
  size_t str_length = size * 2U + 1U;

  char *str = malloc(str_length * sizeof *str);
  if (str != NULL)
  {
    for (size_t i = 0U; i < size; i++)
    {
      str[str_index++] = nibble_to_hex_char(hash[i] >> 4U);
      str[str_index++] = nibble_to_hex_char(hash[i] & 0xFU);
    }

    str[str_index] = '\0';
  }

  return str;
}

/*************************
 *        SHA224
 ************************/
void sha224_init(sha224_ctx *ctx)
{
  ctx->msg_len = 0U;
  ctx->chunk_idx = 0U;

  ctx->h[0U] = 0xc1059ed8U;
  ctx->h[1U] = 0x367cd507U;
  ctx->h[2U] = 0x3070dd17U;
  ctx->h[3U] = 0xf70e5939U;
  ctx->h[4U] = 0xffc00b31U;
  ctx->h[5U] = 0x68581511U;
  ctx->h[6U] = 0x64f98fa7U;
  ctx->h[7U] = 0xbefa4fa4U;
}

void sha224_process(sha224_ctx *ctx, const uint8_t *data, size_t size)
{
  sha256_process(ctx, data, size);
}

void sha224_finalize(sha224_ctx *ctx, uint8_t result[static 28U])
{
  uint8_t hash[32U];
  sha256_finalize(ctx, hash);
  memcpy(result, hash, 28U * sizeof *result);
}

char* sha224_to_string(const uint8_t hash[static 28U])
{
  return hash_to_string(hash, 28U);
}

void sha224(const uint8_t *data, size_t size, uint8_t result[static 28U])
{
  sha224_ctx ctx;

  sha224_init(&ctx);
  sha224_process(&ctx, data, size);
  sha224_finalize(&ctx, result);
}

/*************************
 *        SHA256
 ************************/
void sha256(const uint8_t *data, size_t size, uint8_t result[static 32U])
{
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_process(&ctx, data, size);
  sha256_finalize(&ctx, result);
}

void sha256_init(sha256_ctx *ctx)
{
  ctx->msg_len = 0U;
  ctx->chunk_idx = 0U;

  ctx->h[0U] = 0x6a09e667U;
  ctx->h[1U] = 0xbb67ae85U;
  ctx->h[2U] = 0x3c6ef372U;
  ctx->h[3U] = 0xa54ff53aU;
  ctx->h[4U] = 0x510e527fU;
  ctx->h[5U] = 0x9b05688cU;
  ctx->h[6U] = 0x1f83d9abU;
  ctx->h[7U] = 0x5be0cd19U;
}

void sha256_process(sha256_ctx *ctx, const uint8_t *data, size_t size)
{
  size_t length_to_process;
  size_t data_idx = 0U;

  ctx->msg_len += size;

  while (size > 0U)
  {
    length_to_process = MIN(size, 64U - ctx->chunk_idx);
    memcpy(&ctx->chunk[ctx->chunk_idx], &data[data_idx], length_to_process);

    size -= length_to_process;
    data_idx += length_to_process;
    ctx->chunk_idx += length_to_process;

    if (ctx->chunk_idx == 64U)
    {
      sha2xx_process(ctx);
    }
  }
}

void sha256_finalize(sha256_ctx *ctx, uint8_t result[static 32U])
{
  uint64_t data_bit_length = ctx->msg_len * 8U;

  uint8_t one_bit_padding = 0x80U;
  sha256_process(ctx, &one_bit_padding, 1U);

  size_t padding_length = (ctx->chunk_idx > 56U) ? (56U + 64U - ctx->chunk_idx) : (56U - ctx->chunk_idx);
  sha256_process(ctx, zero_padding, padding_length);

  uint8_t data_bit_length_be_bytes[8U];
  PACK_U64_BE(data_bit_length_be_bytes, 0U, data_bit_length);
  sha256_process(ctx, data_bit_length_be_bytes, sizeof data_bit_length_be_bytes);

  PACK_U32_BE(result, 0U, ctx->h[0U]);
  PACK_U32_BE(result, 4U, ctx->h[1U]);
  PACK_U32_BE(result, 8U, ctx->h[2U]);
  PACK_U32_BE(result, 12U, ctx->h[3U]);
  PACK_U32_BE(result, 16U, ctx->h[4U]);
  PACK_U32_BE(result, 20U, ctx->h[5U]);
  PACK_U32_BE(result, 24U, ctx->h[6U]);
  PACK_U32_BE(result, 28U, ctx->h[7U]);
}

char* sha256_to_string(const uint8_t hash[static 32U])
{
  return hash_to_string(hash, 32U);
}

/*************************
 *        SHA384
 ************************/
void sha384(const uint8_t *data, size_t size, uint8_t result[static 48U])
{
  sha384_ctx ctx;
  sha384_init(&ctx);
  sha384_process(&ctx, data, size);
  sha384_finalize(&ctx, result);
}

void sha384_init(sha384_ctx *ctx)
{
  ctx->msg_len = 0U;
  ctx->chunk_idx = 0U;

  ctx->h[0U] = 0xcbbb9d5dc1059ed8ULL;
  ctx->h[1U] = 0x629a292a367cd507ULL;
  ctx->h[2U] = 0x9159015a3070dd17ULL;
  ctx->h[3U] = 0x152fecd8f70e5939ULL;
  ctx->h[4U] = 0x67332667ffc00b31ULL;
  ctx->h[5U] = 0x8eb44a8768581511ULL;
  ctx->h[6U] = 0xdb0c2e0d64f98fa7ULL;
  ctx->h[7U] = 0x47b5481dbefa4fa4ULL;
}

void sha384_process(sha384_ctx *ctx, const uint8_t *data, size_t size)
{
  sha512_process(ctx, data, size);
}

void sha384_finalize(sha384_ctx *ctx, uint8_t result[static 48U])
{
  uint8_t hash[64U];
  sha512_finalize(ctx, hash);
  memcpy(result, hash, 48U * sizeof *result);
}

char* sha384_to_string(const uint8_t hash[static 48U])
{
  return hash_to_string(hash, 48U);
}

/*************************
 *        SHA512
 ************************/
void sha512(const uint8_t *data, size_t size, uint8_t result[static 64U])
{
  sha512_ctx ctx;
  sha512_init(&ctx);
  sha512_process(&ctx, data, size);
  sha512_finalize(&ctx, result);
}

void sha512_init(sha512_ctx *ctx)
{
  ctx->msg_len = 0U;
  ctx->chunk_idx = 0U;

  ctx->h[0U] = 0x6a09e667f3bcc908ULL;
  ctx->h[1U] = 0xbb67ae8584caa73bULL;
  ctx->h[2U] = 0x3c6ef372fe94f82bULL;
  ctx->h[3U] = 0xa54ff53a5f1d36f1ULL;
  ctx->h[4U] = 0x510e527fade682d1ULL;
  ctx->h[5U] = 0x9b05688c2b3e6c1fULL;
  ctx->h[6U] = 0x1f83d9abfb41bd6bULL;
  ctx->h[7U] = 0x5be0cd19137e2179ULL;
}

void sha512_process(sha512_ctx *ctx, const uint8_t *data, size_t size)
{
  size_t length_to_process;
  size_t data_idx = 0U;

  ctx->msg_len += size;

  while (size > 0U)
  {
    length_to_process = MIN(size, 128U - ctx->chunk_idx);
    memcpy(&ctx->chunk[ctx->chunk_idx], &data[data_idx], length_to_process);

    size -= length_to_process;
    data_idx += length_to_process;
    ctx->chunk_idx += length_to_process;

    if (ctx->chunk_idx == 128U)
    {
      sha5xx_process(ctx);
    }
  }
}

void sha512_finalize(sha512_ctx *ctx, uint8_t result[static 64U])
{
  uint64_t data_bit_length = ctx->msg_len * 8U;

  uint8_t one_bit_padding = 0x80U;
  sha512_process(ctx, &one_bit_padding, 1U);

  size_t padding_length = (ctx->chunk_idx > 112U) ? (112U + 128U - ctx->chunk_idx) : (112U - ctx->chunk_idx);
  sha512_process(ctx, zero_padding, padding_length);

  uint8_t data_bit_length_be_bytes[16U] = {0U};
  PACK_U64_BE(data_bit_length_be_bytes, 8U, data_bit_length);
  sha512_process(ctx, data_bit_length_be_bytes, sizeof data_bit_length_be_bytes);

  PACK_U64_BE(result, 0U,  ctx->h[0U]);
  PACK_U64_BE(result, 8U,  ctx->h[1U]);
  PACK_U64_BE(result, 16U, ctx->h[2U]);
  PACK_U64_BE(result, 24U, ctx->h[3U]);
  PACK_U64_BE(result, 32U, ctx->h[4U]);
  PACK_U64_BE(result, 40U, ctx->h[5U]);
  PACK_U64_BE(result, 48U, ctx->h[6U]);
  PACK_U64_BE(result, 56U, ctx->h[7U]);
}

char* sha512_to_string(const uint8_t hash[static 64U])
{
  return hash_to_string(hash, 64U);
}

/*************************
 *      SHA512/224
 ************************/
void sha512_224(const uint8_t *data, size_t size, uint8_t result[static 28U])
{
  sha512_224_ctx ctx;
  sha512_224_init(&ctx);
  sha512_224_process(&ctx, data, size);
  sha512_224_finalize(&ctx, result);
}

void sha512_224_init(sha512_224_ctx *ctx)
{
  ctx->msg_len = 0U;
  ctx->chunk_idx = 0U;

  ctx->h[0U] = 0x8c3d37c819544da2ULL;
  ctx->h[1U] = 0x73e1996689dcd4d6ULL;
  ctx->h[2U] = 0x1dfab7ae32ff9c82ULL;
  ctx->h[3U] = 0x679dd514582f9fcfULL;
  ctx->h[4U] = 0x0f6d2b697bd44da8ULL;
  ctx->h[5U] = 0x77e36f7304C48942ULL;
  ctx->h[6U] = 0x3f9d85a86a1d36C8ULL;
  ctx->h[7U] = 0x1112e6ad91d692a1ULL;
}

void sha512_224_process(sha512_224_ctx *ctx, const uint8_t *data, size_t size)
{
  sha512_process(ctx, data, size);
}

void sha512_224_finalize(sha512_224_ctx *ctx, uint8_t result[static 28U])
{
  uint8_t hash[32U];
  sha512_256_finalize(ctx, hash);
  memcpy(result, hash, 28U * sizeof *result);
}

char* sha512_224_to_string(const uint8_t hash[static 28U])
{
  return hash_to_string(hash, 28U);
}

/*************************
 *      SHA512/256
 ************************/
void sha512_256(const uint8_t *data, size_t size, uint8_t result[static 32U])
{
  sha512_256_ctx ctx;
  sha512_256_init(&ctx);
  sha512_256_process(&ctx, data, size);
  sha512_256_finalize(&ctx, result);
}

void sha512_256_init(sha512_256_ctx *ctx)
{
  ctx->msg_len = 0U;
  ctx->chunk_idx = 0U;

  ctx->h[0U] = 0x22312194fc2bf72cULL;
  ctx->h[1U] = 0x9f555fa3c84c64c2ULL;
  ctx->h[2U] = 0x2393b86b6f53b151ULL;
  ctx->h[3U] = 0x963877195940eabdULL;
  ctx->h[4U] = 0x96283ee2a88effe3ULL;
  ctx->h[5U] = 0xbe5e1e2553863992ULL;
  ctx->h[6U] = 0x2b0199fc2c85b8aaULL;
  ctx->h[7U] = 0x0eb72ddC81c52ca2ULL;
}

void sha512_256_process(sha512_256_ctx *ctx, const uint8_t *data, size_t size)
{
  sha512_process(ctx, data, size);
}

void sha512_256_finalize(sha512_256_ctx *ctx, uint8_t result[static 32U])
{
  uint8_t hash[64U];
  sha512_finalize(ctx, hash);

  memcpy(result, hash, 32U * sizeof *result);
}

char* sha512_256_to_string(const uint8_t hash[static 32U])
{
  return hash_to_string(hash, 32U);
}
