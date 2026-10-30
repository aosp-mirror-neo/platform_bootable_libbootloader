/*
 * Copyright (C) 2026 The Android Open Source Project
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
 * SPDX-License-Identifier: Apache-2.0 OR BSD-2-Clause-Patent
 *
 * You may choose to use or redistribute this file under
 *  (a) the Apache License, Version 2.0, or
 *  (b) the BSD 2-Clause Patent license.
 *
 * Unless you expressly elect the BSD-2-Clause-Patent terms, the Apache-2.0
 * terms apply by default.
 */

#ifndef __LOAD_FILE2_PROTOCOL_H__
#define __LOAD_FILE2_PROTOCOL_H__

#include <uefi/gbl_protocol_utils.h>
#include <uefi/protocols/device_path_protocol.h>
#include <uefi/types.h>

// {4006c0c1-fcb3-403e-996d-4a6c8724e06d}
EFI_GUID(EFI_LOAD_FILE2_PROTOCOL_GUID, 0x4006c0c1, 0xfcb3, 0x403e, 0x99, 0x6d,
         0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d);

typedef struct EfiLoadFile2Protocol {
  EfiStatus (*load_file)(struct EfiLoadFile2Protocol* self,
                         struct EfiDevicePathProtocol* file_path,
                         bool boot_policy, size_t* buffer_size, void* buffer);
} EfiLoadFile2Protocol;

#endif  // __LOAD_FILE2_PROTOCOL_H__
