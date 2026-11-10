# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@bazel_skylib//rules:build_test.bzl", "build_test")

package(
    default_applicable_licenses = ["@gbl//licensing:gbl_license"],
    default_visibility = ["//visibility:public"],
)

# Build-only coverage for targets that aren't reachable from `gbl_efi_dist` or
# any test, so that presubmit catches breakages in them.
build_test(
    name = "extra_targets_build_test",
    targets = [
        "@gbl//efi:aarch64_debug_dev",
        "@gbl//efi:aarch64_debug_prod",
        "@gbl//efi:x86_64_debug_dev",
        "@gbl//efi:x86_64_debug_prod",
        "@gbl//protocol_integration:protocol_integration_optional",
        "@gbl//protocol_integration:protocol_integration_required",
    ],
)

test_suite(
    name = "tests",
    tests = [
        ":extra_targets_build_test",
        "@gbl//:readme_test",
        "@gbl//efi:test",
        "@gbl//efi:test_dev",
        "@gbl//libabr:libabr_tests",
        "@gbl//libasync:libasync_test",
        "@gbl//libboot:libboot_test",
        "@gbl//libbootimg:libbootimg_test",
        "@gbl//libbootparams:test",
        "@gbl//libboringssl:crypto_test",
        "@gbl//libboringssl:sysdeps_test",
        "@gbl//libbuild_number:libbuild_number_test",
        "@gbl//libc:libc_c_test",
        "@gbl//libc:libc_test",
        "@gbl//libdecompress:libdecompress_test",
        "@gbl//libdttable:libdttable_test",
        "@gbl//libefi:efi_avb_test",
        "@gbl//libefi:libefi_test",
        "@gbl//libefi:libefi_test_dev",
        "@gbl//libefi:mocks_test",
        "@gbl//libefi_types:gbl_protocols_license_test",
        "@gbl//libefi_types:libefi_types_doc_test",
        "@gbl//libefi_types:libefi_types_test",
        "@gbl//libelf:relocation_test",
        "@gbl//liberror:liberror_test",
        "@gbl//libfastboot:libfastboot_test",
        "@gbl//libfdt:libfdt_test",
        "@gbl//libfit:libfit_test",
        "@gbl//libgbl:libgbl_test",
        "@gbl//libgbl:libgbl_test_dev",
        "@gbl//libgblutils:test",
        "@gbl//libgblutils:testutils_test",
        "@gbl//liblp:liblp_test",
        "@gbl//libmisc:libmisc_test",
        "@gbl//libopendice:libopendice_test",
        "@gbl//libpvmfwconfig:libpvmfwconfig_test",
        "@gbl//libsafemath:libsafemath_test",
        "@gbl//libstorage:libstorage_doc_test",
        "@gbl//libstorage:libstorage_test",
        "@gbl//libutils:test",
        "@gbl//signtool:gblsigntool_test",
        "@gbl//tests/qemu:tests",
    ],
)
