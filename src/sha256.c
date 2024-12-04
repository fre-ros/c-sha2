#include "sha256.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define RROTATE(n, r) (((n) << (32U - (r))) | ((n) >> (r)))

#define UNPACK_U32_BE(arr, i) (((uint32_t)arr[i]    << 24U) | \
                               ((uint32_t)arr[i+1U] << 16U) | \
                               ((uint32_t)arr[i+2U] << 8U)  | \
                               ((uint32_t)arr[i+3U] << 0U))

static const uint32_t k[64U] = {
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

static void sha256_process(struct sha256_ctx *ctx)
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
    uint32_t s0 = RROTATE(w[i-15U], 7U) ^ RROTATE(w[i-15U], 18U) ^ (w[i-15U] >> 3U);
    uint32_t s1 = RROTATE(w[i-2U], 17U) ^ RROTATE(w[i-2U], 19U)  ^ (w[i-2U] >> 10U);
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
    uint32_t S1     = RROTATE(e, 6U) ^ RROTATE(e, 11U) ^ RROTATE(e, 25U);
    uint32_t ch     = (e & f) ^ ((~e) & g);
    uint32_t temp1  = h + S1 + ch + k[i] + w[i];
    uint32_t S0     = RROTATE(a, 2U) ^ RROTATE(a, 13U) ^ RROTATE(a, 22U);
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

void sha256_init(struct sha256_ctx *ctx)
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

void sha256_feed(struct sha256_ctx *ctx, const uint8_t *data, size_t size)
{
  uint32_t len_to_add;
  uint32_t data_idx = 0U;

  while (size > 0U)
  {
    len_to_add = MIN(size, 64U - ctx->chunk_idx);
    memcpy(&ctx->chunk[ctx->chunk_idx], &data[data_idx], len_to_add);

    size -= len_to_add;
    data_idx += len_to_add;
    ctx->msg_len += len_to_add;
    ctx->chunk_idx += len_to_add;

    if (ctx->chunk_idx == 64U)
    {
      sha256_process(ctx);
    }
  }
}

void sha256_finalize(struct sha256_ctx *ctx, uint32_t result[static 8U])
{
  uint64_t data_bit_length = ctx->msg_len * 8U;
  uint8_t data_bit_length_be_bytes[8U] =
  {
    (data_bit_length >> 56U) & 0xFFU,
    (data_bit_length >> 48U) & 0xFFU,
    (data_bit_length >> 40U) & 0xFFU,
    (data_bit_length >> 32U) & 0xFFU,
    (data_bit_length >> 24U) & 0xFFU,
    (data_bit_length >> 16U) & 0xFFU,
    (data_bit_length >> 8U) & 0xFFU,
    (data_bit_length >> 0U) & 0xFFU
  };

  uint8_t one_bit_padding = 0x80U;
  sha256_feed(ctx, &one_bit_padding, 1U);

  uint8_t zero_padding[64U] = {0U};
  size_t padding_length = (ctx->chunk_idx > 56U) ? (56U + 64U - ctx->chunk_idx) : (56U - ctx->chunk_idx);
  sha256_feed(ctx, zero_padding, padding_length);

  sha256_feed(ctx, data_bit_length_be_bytes, sizeof data_bit_length_be_bytes);

  result[0U] = ctx->h[0U];
  result[1U] = ctx->h[1U];
  result[2U] = ctx->h[2U];
  result[3U] = ctx->h[3U];
  result[4U] = ctx->h[4U];
  result[5U] = ctx->h[5U];
  result[6U] = ctx->h[6U];
  result[7U] = ctx->h[7U];
}

void sha256(const uint8_t *data, size_t size, uint32_t result[static 8U])
{
  struct sha256_ctx ctx;

  sha256_init(&ctx);
  sha256_feed(&ctx, data, size);
  sha256_finalize(&ctx, result);
}

char* sha256_to_string(const uint32_t hash[static 8U])
{
  // 8 characters per uint32_t plus NULL terminator
  size_t str_length = 8U * 8U + 1U;

  char *str = malloc(str_length * sizeof *str);
  if (str != NULL)
  {
    sprintf(
      str,
      "%.8"PRIx32"%.8"PRIx32"%.8"PRIx32"%.8"PRIx32"%.8"PRIx32"%.8"PRIx32"%.8"PRIx32"%.8"PRIx32,
      hash[0U], hash[1U], hash[2U], hash[3U], hash[4U], hash[5U], hash[6U], hash[7U]
    );
  }

  return str;
}
