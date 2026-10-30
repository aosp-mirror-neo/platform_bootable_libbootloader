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
 *
 */
#include "libavb/avb_sha.h"

#include "efi_sha_c.h"
#include "libavb/avb_crypto_ops_impl.h"

// Safety: `ctx` must be null (which aborts) or point to a valid, writable,
// properly aligned `AvbSHA256Ctx`.
void avb_sha256_init(AvbSHA256Ctx* ctx) {
  if (ctx == NULL) {
    avb_abort();
  }
  // SAFETY: `ctx` is non-null and points to a valid `AvbSHA256Ctx` by caller
  // precondition, so `&ctx->impl.state.efi_hasher` is writable, properly
  // aligned storage for `EfiHasherStorage`.
  if (efi_sha256_init(&ctx->impl.state.efi_hasher)) {
    ctx->impl.tag = AVB_HASH_EFI;
  } else {
    ctx->impl.tag = AVB_HASH_SSL;
    SHA256_Init(&ctx->impl.state.ssl_ctx);
  }
}

// Safety:
// * `ctx` must be null (which aborts) or point to a valid `AvbSHA256Ctx`
//   initialized by `avb_sha256_init` during the current boot services session
//   and not yet finalized.
// * If `len != 0`, `data` must be null (which aborts) or valid to read for
//   `len` bytes.
void avb_sha256_update(AvbSHA256Ctx* ctx, const uint8_t* data, size_t len) {
  if (ctx == NULL || (data == NULL && len != 0)) {
    avb_abort();
  }
  if (ctx->impl.tag == AVB_HASH_EFI) {
    // SAFETY:
    // * `ctx` is non-null and `ctx->impl.tag == AVB_HASH_EFI`, which is set
    //   only after `efi_sha256_init` succeeds and cleared in
    //   `avb_sha256_final`, so `efi_hasher` holds an active initialized hasher.
    // * `data` is non-null when `len != 0`, and valid for `len` bytes by caller
    //   precondition.
    efi_sha256_update(&ctx->impl.state.efi_hasher, data, len);
  } else if (ctx->impl.tag == AVB_HASH_SSL) {
    SHA256_Update(&ctx->impl.state.ssl_ctx, data, len);
  } else {
    avb_abort();
  }
}

// Safety: `ctx` must be null (which aborts) or point to a valid `AvbSHA256Ctx`
// initialized by `avb_sha256_init` during the current boot services session and
// not yet finalized.
uint8_t* avb_sha256_final(AvbSHA256Ctx* ctx) {
  if (ctx == NULL) {
    avb_abort();
  }
  if (ctx->impl.tag == AVB_HASH_EFI) {
    // SAFETY:
    // * `ctx` is non-null and `ctx->impl.tag == AVB_HASH_EFI` (cleared to
    //   `AVB_HASH_UNKNOWN` below so the hasher cannot be used again), so
    //   `efi_hasher` holds an active initialized hasher.
    // * `ctx->buf` is writable storage of `AVB_SHA256_DIGEST_SIZE` (32) bytes.
    efi_sha256_final(&ctx->impl.state.efi_hasher, ctx->buf);
  } else if (ctx->impl.tag == AVB_HASH_SSL) {
    SHA256_Final(ctx->buf, &ctx->impl.state.ssl_ctx);
  } else {
    avb_abort();
  }

  ctx->impl.tag = AVB_HASH_UNKNOWN;
  return ctx->buf;
}

// Safety: `ctx` must be null (which aborts) or point to a valid, writable,
// properly aligned `AvbSHA512Ctx`.
void avb_sha512_init(AvbSHA512Ctx* ctx) {
  if (ctx == NULL) {
    avb_abort();
  }
  // SAFETY: `ctx` is non-null and points to a valid `AvbSHA512Ctx` by caller
  // precondition, so `&ctx->impl.state.efi_hasher` is writable, properly
  // aligned storage for `EfiHasherStorage`.
  if (efi_sha512_init(&ctx->impl.state.efi_hasher)) {
    ctx->impl.tag = AVB_HASH_EFI;
  } else {
    ctx->impl.tag = AVB_HASH_SSL;
    SHA512_Init(&ctx->impl.state.ssl_ctx);
  }
}

// Safety:
// * `ctx` must be null (which aborts) or point to a valid `AvbSHA512Ctx`
//   initialized by `avb_sha512_init` during the current boot services session
//   and not yet finalized.
// * If `len != 0`, `data` must be null (which aborts) or valid to read for
//   `len` bytes.
void avb_sha512_update(AvbSHA512Ctx* ctx, const uint8_t* data, size_t len) {
  if (ctx == NULL || (data == NULL && len != 0)) {
    avb_abort();
  }
  if (ctx->impl.tag == AVB_HASH_EFI) {
    // SAFETY:
    // * `ctx` is non-null and `ctx->impl.tag == AVB_HASH_EFI`, which is set
    //   only after `efi_sha512_init` succeeds and cleared in
    //   `avb_sha512_final`, so `efi_hasher` holds an active initialized hasher.
    // * `data` is non-null when `len != 0`, and valid for `len` bytes by caller
    //   precondition.
    efi_sha512_update(&ctx->impl.state.efi_hasher, data, len);
  } else if (ctx->impl.tag == AVB_HASH_SSL) {
    SHA512_Update(&ctx->impl.state.ssl_ctx, data, len);
  } else {
    avb_abort();
  }
}

// Safety: `ctx` must be null (which aborts) or point to a valid `AvbSHA512Ctx`
// initialized by `avb_sha512_init` during the current boot services session and
// not yet finalized.
uint8_t* avb_sha512_final(AvbSHA512Ctx* ctx) {
  if (ctx == NULL) {
    avb_abort();
  }
  if (ctx->impl.tag == AVB_HASH_EFI) {
    // SAFETY:
    // * `ctx` is non-null and `ctx->impl.tag == AVB_HASH_EFI` (cleared to
    //   `AVB_HASH_UNKNOWN` below so the hasher cannot be used again), so
    //   `efi_hasher` holds an active initialized hasher.
    // * `ctx->buf` is writable storage of `AVB_SHA512_DIGEST_SIZE` (64) bytes.
    efi_sha512_final(&ctx->impl.state.efi_hasher, ctx->buf);
  } else if (ctx->impl.tag == AVB_HASH_SSL) {
    SHA512_Final(ctx->buf, &ctx->impl.state.ssl_ctx);
  } else {
    avb_abort();
  }

  ctx->impl.tag = AVB_HASH_UNKNOWN;
  return ctx->buf;
}
