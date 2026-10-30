/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bindgen_unified_header.h>
#include <efi_sha_c.h>
#include <gtest/gtest.h>
#include <openssl/sha2.h>

#include <array>
#include <string_view>

class EfiShaTraces {
 public:
  explicit EfiShaTraces(bool success)
      : init_success(success),
        init_call_count(0),
        update_call_count(0),
        final_call_count(0) {}

  EfiShaTraces() : EfiShaTraces(false) {}
  EfiShaTraces(EfiShaTraces const&) = default;
  EfiShaTraces(EfiShaTraces&&) = default;

  EfiShaTraces& operator=(EfiShaTraces const&) = default;
  EfiShaTraces& operator=(EfiShaTraces&&) = default;

  bool init_success;
  uint32_t init_call_count;

  uint32_t update_call_count;

  uint32_t final_call_count;
};

constexpr std::string_view MESSAGE =
    "On a real world west of wonder, somewhere, nowhere all.";

thread_local EfiShaTraces SHA256_TRACES;

extern "C" {
bool efi_sha256_init(EfiHasherStorage* hasher) {
  SHA256_TRACES.init_call_count++;
  return SHA256_TRACES.init_success;
}

void efi_sha256_update(EfiHasherStorage* hasher, uint8_t const* data,
                       size_t len) {
  SHA256_TRACES.update_call_count++;
}

void efi_sha256_final(EfiHasherStorage* hasher,
                      uint8_t out[AVB_SHA256_DIGEST_SIZE]) {
  SHA256_TRACES.final_call_count++;
}
}

TEST(EfiShaTest, Sha256Ssl) {
  AvbSHA256Ctx ctx;
  // Returning false from efi_sha256_init means that avb_sha256_init considers
  // the attempt to make a Hasher to have failed and falls back to a BoringSSL
  // implementation.
  SHA256_TRACES = EfiShaTraces();
  avb_sha256_init(&ctx);
  avb_sha256_update(&ctx, reinterpret_cast<const uint8_t*>(MESSAGE.data()),
                    MESSAGE.size());
  uint8_t* digest = avb_sha256_final(&ctx);
  ASSERT_EQ(digest, ctx.buf);

  ASSERT_EQ(SHA256_TRACES.init_call_count, 1);
  ASSERT_EQ(SHA256_TRACES.update_call_count, 0);
  ASSERT_EQ(SHA256_TRACES.final_call_count, 0);

  std::array<uint8_t, AVB_SHA256_DIGEST_SIZE> expected;
  std::ignore = SHA256(reinterpret_cast<const uint8_t*>(MESSAGE.data()),
                       MESSAGE.size(), expected.data());

  std::array<uint8_t, AVB_SHA256_DIGEST_SIZE> actual;
  std::copy(std::cbegin(ctx.buf), std::cend(ctx.buf), actual.begin());
  ASSERT_EQ(actual, expected);
}

TEST(EfiShaTest, Sha256Efi) {
  AvbSHA256Ctx ctx;
  // Making efi_sha256_init return true means avb_sha256_init uses the Hasher
  // based implementation.
  SHA256_TRACES = EfiShaTraces(true);

  avb_sha256_init(&ctx);
  avb_sha256_update(&ctx, reinterpret_cast<const uint8_t*>(MESSAGE.data()),
                    MESSAGE.size());
  std::ignore = avb_sha256_final(&ctx);

  ASSERT_EQ(SHA256_TRACES.init_call_count, 1);
  ASSERT_EQ(SHA256_TRACES.update_call_count, 1);
  ASSERT_EQ(SHA256_TRACES.final_call_count, 1);
}

thread_local EfiShaTraces SHA512_TRACES;
extern "C" {
bool efi_sha512_init(EfiHasherStorage* hasher) {
  SHA512_TRACES.init_call_count++;
  return SHA512_TRACES.init_success;
}

void efi_sha512_update(EfiHasherStorage* hasher, uint8_t const* data,
                       size_t len) {
  SHA512_TRACES.update_call_count++;
}

void efi_sha512_final(EfiHasherStorage* hasher,
                      uint8_t out[AVB_SHA512_DIGEST_SIZE]) {
  SHA512_TRACES.final_call_count++;
}
}

TEST(EfiShaTest, Sha512Ssl) {
  AvbSHA512Ctx ctx;
  // Returning false from efi_sha512_init means that avb_sha512_init considers
  // the attempt to make a Hasher to have failed and falls back to a BoringSSL
  // implementation.
  SHA512_TRACES = EfiShaTraces();
  avb_sha512_init(&ctx);
  avb_sha512_update(&ctx, reinterpret_cast<const uint8_t*>(MESSAGE.data()),
                    MESSAGE.size());
  uint8_t* digest = avb_sha512_final(&ctx);
  ASSERT_EQ(digest, ctx.buf);

  ASSERT_EQ(SHA512_TRACES.init_call_count, 1);
  ASSERT_EQ(SHA512_TRACES.update_call_count, 0);
  ASSERT_EQ(SHA512_TRACES.final_call_count, 0);

  std::array<uint8_t, AVB_SHA512_DIGEST_SIZE> expected;
  std::ignore = SHA512(reinterpret_cast<const uint8_t*>(MESSAGE.data()),
                       MESSAGE.size(), expected.data());

  std::array<uint8_t, AVB_SHA512_DIGEST_SIZE> actual;
  std::copy(std::cbegin(ctx.buf), std::cend(ctx.buf), actual.begin());
  ASSERT_EQ(actual, expected);
}

TEST(EfiShaTest, Sha512Efi) {
  AvbSHA512Ctx ctx;
  // Making efi_sha512_init return true means avb_sha512_init uses the Hasher
  // based implementation.
  SHA512_TRACES = EfiShaTraces(true);

  avb_sha512_init(&ctx);
  avb_sha512_update(&ctx, reinterpret_cast<const uint8_t*>(MESSAGE.data()),
                    MESSAGE.size());
  std::ignore = avb_sha512_final(&ctx);

  ASSERT_EQ(SHA512_TRACES.init_call_count, 1);
  ASSERT_EQ(SHA512_TRACES.update_call_count, 1);
  ASSERT_EQ(SHA512_TRACES.final_call_count, 1);
}
