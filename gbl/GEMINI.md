# Generic Bootloader (GBL)

GBL is a UEFI application encapsulating the Android and Fuchsia boot processes,
providing a standardized, platform-agnostic bootloader core.

## Architecture & Design

- **Design:** Connects to EFI APIs through a platform hook model.
- **Goal:** Reduce code duplication in board-specific firmware.
- **Tech Stack:**
  - **Rust:** Core logic (safety-critical).
  - **C:** Hardware interactions and foundational libraries.
  - **Bazel:** Build system.
  - **Clang:** Compiler (via `<monorepo-root>/prebuilts/`).

## Directory Structure Map

- `docs/`: User-facing documentation (for device makers).
- `efi/`: UEFI application binaries.
- `lib*/`: Independent libraries prioritized for modularity.
- `libefi/`: EFI platform hooks connecting core logic to the UEFI environment.
- `libefi_types/`: EFI C declarations and Rust wrappers (No logic).
- `libgbl/`: Core platform-agnostic logic.

## Engineering Standards

### 1. Environment Constraints

- **Target:** Bare-metal UEFI.
- **Rust `no_std`:** Production code MUST declare
  `#![cfg_attr(not(test), no_std)]`. Rely exclusively on `core` and `alloc`.
- **Memory Allocation:** Dynamic allocations (hooked into UEFI) are available
  but highly discouraged in production, where stack allocation or a scratch
  buffer (for large data) is preferred.
- **Memory Allocation in unit tests:** Dynamic allocations are perfectly
  acceptable.

### 2. Testing Constraints

- **Target:** Hosted environment with `std` enabled.
- **Strategy:** Heavily mock UEFI services.
- **Concurrency:** The test runner is multi-threaded. Use `Arc`, `Mutex`,
  `atomics`, or `thread_local!` when testing code that interacts with global
  state (e.g., panic hooks) to prevent race conditions.

### 3. Error Handling

- **Recoverable Errors:** Return `Result` when a caller may be able to handle
  the error, e.g. by falling back to fastboot on a corrupt disk, trying the
  other slot, or rejecting invalid host input while staying in fastboot. If code
  can't tell whether its errors are recoverable (common in libraries), return
  `Result` and let something higher in the call stack make the decision.
- **Unrecoverable Errors:** Once code knows an error is unrecoverable, stop at
  that point instead of propagating an error that would only fail in `main()`.
  Avoid `unwrap()` and `panic!()` without a message; use one of:
  - **`expect()`:** The default, or `panic!()` with a message if there's no
    `Option` or `Result`. The message should briefly say what went wrong; the
    location is already logged, so don't repeat it. The panic handler logs the
    message and location to the console, passes the frame pointer to the GBL
    debug protocol so firmware can capture a backtrace, and resets. A
    propagated error usually loses this context.
  - **`report_error_and_reset()`:** For well-defined failure categories that
    devices may want to track explicitly. Panics are reported to firmware with
    the generic `GBL_EFI_DEBUG_ERROR_TAG_ASSERTION_ERROR` tag, while this passes
    a specific `GblEfiDebugErrorTag`. For example, failing to find any block
    devices at startup reports `GBL_EFI_DEBUG_ERROR_TAG_PARTITION`. Tags exist
    for device needs, so only add a new one when a device needs to track that
    failure.
- **C Libraries:** Some crates are also built as C static libraries for other
  firmware (e.g. `libabr_c`). These don't run inside GBL, so GBL's panic handler
  and `report_error_and_reset()` aren't available; a panic goes to the
  library's own handler instead (`libabr_c` calls the integrator's
  `AbrAbort()`). Report errors through the documented C error codes (e.g.
  `ABR_RESULT_ERR_IO`) so the integrator can handle them, and only panic on
  fatal unrecoverable conditions.

### 4. Coding Conventions

- **Imports:** ALWAYS use imports at the module top level unless a name is used
  only once or is ambiguous. When adding new imports, merge and group them with
  existing ones sharing a common prefix (e.g., `use crate::ops::{A, B, C};`)
  instead of adding standalone lines, to preserve file style.
- **Contextual Awareness:** ALWAYS prioritize understanding and matching the
  local context of the file and component you are working on. This applies to
  coding style (like import grouping), architectural patterns, error handling,
  and dependency usage. Read surrounding code and existing implementations to
  understand established patterns before introducing new code or structures.

## Building and Testing

The GBL build script is at `bootable/libbootloader/gbl/bazel.sh` relative to the
repo root.

### Building the EFI application

```bash
./bazel.sh run //bootable/libbootloader:gbl_efi_dist
```

### Running unit tests

```bash
./bazel.sh test @gbl//tests
```

## Formatting

Always format code using the following tools before committing.

- **Rust:** `rustfmt <file>`
- **Python:** `pyink <file_or_directory>`
- **C++:** Adhere to Google C++ Style. Use `clang-format -i <file>`.
- **Markdown:** `prettier --write <file>`

## Contribution Guidelines

Follow these standard Android Open Source Project (AOSP) practices for all
contributions.

### 1. Workflow

- **Branching:** Use the `repo` tool.
- **Code Review:** Submit via Gerrit using `repo upload`.

### 2. Commit Messages

All commit messages must strictly adhere to the Android convention.

- A `Bug:` or `Fix:` tag is **mandatory**.
- A `Test:` tag describing how the change was verified is recommended.

**Format Example:**

```text
gbl: Resolve boot failure on device XYZ

This change addresses a null pointer dereference in the EFI
protocol handling, which caused a boot hang.

Bug: <bug-number>
Test: ./bazel.sh test @gbl//tests
```
