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

#ifndef __EFI_SHA_C_H__
#define __EFI_SHA_C_H__

#include <stdbool.h>

#include "libavb/avb_sha.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Initializes a SHA-256 EFI hasher in-place in `hasher` and returns true on
/// success. Ownership of the hasher is passed to the caller.
///
/// Safety:
/// * `hasher` points to writable, properly aligned `EfiHasherStorage`.
bool efi_sha256_init(EfiHasherStorage* hasher);

/// Adds data to an initialized SHA-256 `EfiHasherStorage` context.
///
/// Safety:
/// * `hasher` points to an `EfiHasherStorage` initialized by `efi_sha256_init`
///   during the current boot services session and not yet finalized.
/// * If `len != 0`, `data` is valid to read for `len` bytes.
void efi_sha256_update(EfiHasherStorage* hasher, uint8_t const* data,
                       size_t len);

/// Consumes an initialized SHA-256 `EfiHasherStorage` and writes its digest to
/// `out`.
///
/// Safety:
/// * `hasher` points to an `EfiHasherStorage` initialized by `efi_sha256_init`
///   during the current boot services session and not yet finalized.
/// * `out` is valid to write for `AVB_SHA256_DIGEST_SIZE` (32) bytes.
void efi_sha256_final(EfiHasherStorage* hasher,
                      uint8_t out[AVB_SHA256_DIGEST_SIZE]);

/// Initializes a SHA-512 EFI hasher in-place in `hasher` and returns true on
/// success. Ownership of the hasher is passed to the caller.
///
/// Safety:
/// * `hasher` points to writable, properly aligned `EfiHasherStorage`.
bool efi_sha512_init(EfiHasherStorage* hasher);

/// Adds data to an initialized SHA-512 `EfiHasherStorage` context.
///
/// Safety:
/// * `hasher` points to an `EfiHasherStorage` initialized by `efi_sha512_init`
///   during the current boot services session and not yet finalized.
/// * If `len != 0`, `data` is valid to read for `len` bytes.
void efi_sha512_update(EfiHasherStorage* hasher, uint8_t const* data,
                       size_t len);

/// Consumes an initialized SHA-512 `EfiHasherStorage` and writes its digest to
/// `out`.
///
/// Safety:
/// * `hasher` points to an `EfiHasherStorage` initialized by `efi_sha512_init`
///   during the current boot services session and not yet finalized.
/// * `out` is valid to write for `AVB_SHA512_DIGEST_SIZE` (64) bytes.
void efi_sha512_final(EfiHasherStorage* hasher,
                      uint8_t out[AVB_SHA512_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif  // __EFI_SHA_C_H__
