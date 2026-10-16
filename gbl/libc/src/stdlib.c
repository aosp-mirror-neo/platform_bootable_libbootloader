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
 */

#include <locale.h>
#include <nl_types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int errno = 0;

#ifdef __GBL_LIBC_STUBS__

extern void* bsearch_rust(const void* key, const void* base, size_t nmemb,
                          size_t size, int (*compar)(const void*, const void*));

void* bsearch(const void* key, const void* base, size_t nmemb, size_t size,
              int (*compar)(const void*, const void*)) {
  return bsearch_rust(key, base, nmemb, size, compar);
}

extern void* gbl_malloc(size_t request_size, size_t alignment);
extern void gbl_free(void* ptr, size_t alignment);
extern void* gbl_realloc(void* ptr, size_t new_size, size_t alignment);

void* malloc(size_t size) { return gbl_malloc(size, _Alignof(max_align_t)); }
void free(void* ptr) { gbl_free(ptr, _Alignof(max_align_t)); }

void* realloc(void* ptr, size_t size) {
  return gbl_realloc(ptr, size, _Alignof(max_align_t));
}

#endif  // __GBL_LIBC_STUBS__
