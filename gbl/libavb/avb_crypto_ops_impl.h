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

#ifndef __AVB_CRYPTO_OPS_IMPL_H__
#define __AVB_CRYPTO_OPS_IMPL_H__

#include <openssl/is_boringssl.h>
#include <openssl/sha.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum : uint8_t {
  AVB_HASH_UNKNOWN,
  AVB_HASH_SSL,
  AVB_HASH_EFI,
} AVB_SHA_CTX_TAG;

// Opaque storage for a detached Rust `RawHasher` (four raw UEFI pointers).
// Using `void*` preserves pointer provenance across FFI without cross-type
// pointer casts on the Rust side.
typedef struct {
  void* opaque[4];
} EfiHasherStorage;

typedef struct {
  union {
    SHA256_CTX ssl_ctx;
    EfiHasherStorage efi_hasher;
  } state;
  AVB_SHA_CTX_TAG tag;
} AvbSHA256ImplCtx;

typedef struct {
  union {
    SHA512_CTX ssl_ctx;
    EfiHasherStorage efi_hasher;
  } state;
  AVB_SHA_CTX_TAG tag;
} AvbSHA512ImplCtx;

// TODO(b/413054304#comment8): migrate to real boringssl types.
typedef struct {
  int dummy;
} AvbMLDSA65PrehashImplCtx;
typedef struct {
  int dummy;
} AvbMLDSA87PrehashImplCtx;

#ifdef __cplusplus
}
#endif

#endif  // __AVB_CRYPTO_OPS_IMPL_H__
