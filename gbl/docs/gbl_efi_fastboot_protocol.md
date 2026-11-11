# GBL EFI Fastboot Protocol

|                |            |
| :------------- | :--------- |
| **Status**     | Stable     |
| **Created**    | 2024-9-11  |
| **Stabilized** | 2026-05-22 |

This document describes the GBL Fastboot protocol. The protocol defines
interfaces that can be used by EFI applications to query and modify
vendor-specific information on a device that may be desired in the context of a
fastboot environment.

## GBL_EFI_FASTBOOT_PROTOCOL

### Summary

This protocol provides interfaces for platform-specific operations during
Fastboot. This includes support for vendor-defined variables or variables whose
query requires cooperation with vendor firmware, as well as OEM commands.

### GUID

```c
// {c67e48a0-5eb8-4127-be89-df2ed93d8a9a}
#define GBL_EFI_FASTBOOT_PROTOCOL_GUID               \
  {                                                  \
    0xc67e48a0, 0x5eb8, 0x4127, {                    \
      0xbe, 0x89, 0xdf, 0x2e, 0xd9, 0x3d, 0x8a, 0x9a \
    }                                                \
  }
```

### Revision Number

```c
#define GBL_EFI_FASTBOOT_PROTOCOL_REVISION GBL_PROTOCOL_REVISION(1, 0)
```

See [GBL Custom Protocol Revisions][custom_protocol_revisions] for details about
protocol revisions.

### Protocol Interface Structure

```c
#define GBL_EFI_FASTBOOT_SERIAL_NUMBER_MAX_LEN_UTF8 32

typedef struct _GBL_EFI_FASTBOOT_PROTOCOL {
  UINT64                              Revision;
  CHAR8                               SerialNumber[GBL_EFI_FASTBOOT_SERIAL_NUMBER_MAX_LEN_UTF8];
  GBL_EFI_FASTBOOT_GET_VAR            GetVar;
  GBL_EFI_FASTBOOT_GET_VAR_ALL        GetVarAll;
  GBL_EFI_FASTBOOT_GET_STAGED         GetStaged;
  GBL_EFI_FASTBOOT_COMMAND_EXEC       CommandExec;
  GBL_EFI_FASTBOOT_GET_PARTITION_TYPE GetPartitionType;
} GBL_EFI_FASTBOOT_PROTOCOL;
```

### Parameters

#### Revision

The revision to which the `GBL_EFI_FASTBOOT_PROTOCOL` adheres. All future
revisions must be backwards compatible. If a future version is not backwards
compatible, a different GUID must be used.

#### SerialNumber

The device serial number expressed as a null-terminated UTF-8 encoded string. If
the device serial number is 32 bytes long, the null terminator must be excluded.
If the device serial number is longer than 32 bytes, it must be truncated.

#### GetVar

Retrieves the value for the given Fastboot variable. See [`GetVar()`][get_var]
for more information.

#### GetVarAll

Iterates over all combinations of arguments and values for all Fastboot
variables. See [`GetVarAll()`][get_var_all] for more information.

#### GetStaged

Reads OEM-provided payload for uploading to the Fastboot host via the
`fastboot get_staged` command. See [`GetStaged()`][get_staged] for more
information.

#### CommandExec

Allows custom overriding of Fastboot commands. See
[`CommandExec()`][command_exec] for more information.

#### GetPartitionType

Retrieves the type of a partition. See
[`GetPartitionType()`][get_partition_type] for more information.

## GBL_EFI_FASTBOOT_PROTOCOL.GetVar()

### Summary

Gets the value for a Fastboot variable.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_FASTBOOT_GET_VAR)(
  IN GBL_EFI_FASTBOOT_PROTOCOL *Self,
  IN UINTN                     NumArgs,
  IN CONST CHAR8 * CONST       *Args,
  IN OUT UINTN                 *BufferSize,
  OUT CHAR8                    *Buffer
  );
```

### Parameters

#### Self

A pointer to the `GBL_EFI_FASTBOOT_PROTOCOL` instance.

#### NumArgs

The number of elements in the `Args` array.

#### Args

A pointer to an array of null-terminated strings that contains the name of the
variable followed by additional arguments.

#### BufferSize

On entry, the size in bytes of `Buffer`. On exit, the size in bytes of the UTF-8
encoded string describing the value, excluding any null-terminator.

#### Buffer

A pointer to the data buffer to store the value of the variable as a UTF-8
encoded string.

### Description

`GetVar()` queries internal data structures and drivers to determine the value
of the given variable. Variables may have zero or more additional arguments.
These arguments are parsed by the caller and passed to `GetVar()` as an array of
NULL-terminated UTF-8 encoded string.

An example client interaction:

```bash
# A variable with no argument.
$ fastboot getvar max-download-size
OKAY0x20000000

# A variable with two arguments.
$ fastboot getvar block-device:0:total-blocks
OKAY0x800000000000
```

### Status Codes Returned

| Return Code             | Semantics                                                                                                                                                                 |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `EFI_SUCCESS`           | The variable was found and its value successfully serialized.                                                                                                             |
| `EFI_INVALID_PARAMETER` | One of `Self`, `Args`, `BufferSize` or `Buffer` is `NULL`.                                                                                                                |
| `EFI_NOT_FOUND`         | The first element of `Args` does not contain a known variable.                                                                                                            |
| `EFI_UNSUPPORTED`       | The contents of `Args` do not contain a known variable with valid arguments. Any of the subarguments may be unknown, or too many or too few subarguments may be provided. |
| `EFI_BUFFER_TOO_SMALL`  | `Buffer` is too small to store the serialized variable string. The value of `BufferSize` is modified to contain the minimum necessary buffer size.                        |

## GBL_EFI_FASTBOOT_PROTOCOL.GetVarAll()

### Summary

Iterates all combinations of variables and values.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_FASTBOOT_GET_VAR_ALL)(
  IN GBL_EFI_FASTBOOT_PROTOCOL    *Self,
  IN VOID                         *Context,
  IN GBL_EFI_GET_VAR_ALL_CALLBACK GetVarAllCallback
  );
```

### Parameters

#### Self

A pointer to the `GBL_EFI_FASTBOOT_PROTOCOL` instance.

#### Context

A pointer to the context data for `GetVarAllCallback`.

#### GetVarAllCallback

A pointer to a function of type `GBL_EFI_GET_VAR_ALL_CALLBACK`. It receives as
parameters the `Context` pointer passed to this function, the array length, an
array of null-terminated UTF-8 strings containing the variable name and
additional arguments, and a null-terminated string representing the value.

### Related Definitions

#### GBL_EFI_GET_VAR_ALL_CALLBACK

```c
typedef
VOID
(*GBL_EFI_GET_VAR_ALL_CALLBACK)(
  IN VOID                *Context,
  IN UINTN               NumArgs,
  IN CONST CHAR8 * CONST *Args,
  IN CONST CHAR8         *Value
  );
```

##### Context

The pointer to the context passed to `GetVarAll()`.

##### NumArgs

The number of elements in the `Args` array.

##### Args

A pointer to an array of null-terminated strings that contains the name of the
variable followed by additional arguments.

The name and arguments correspond to the `:` separated variable format by the
Fastboot protocol, i.e. `fastboot getvar <name>:<arg1>:<arg2>..`. However,
firmware may also choose to pass the entire `"<name>:<arg1>:<arg2>.."` string as
a 1-size array if preferred. Callers should expect both cases.

##### Value

A null-terminated string representing the value.

### Description

`GetVarAll()` iterates all combinations of arguments and values for all fastboot
variables. For each combination, the function invokes the caller provided
callback `GetVarAllCallback()` and passes the context, arguments and value.

### Status Codes Returned

| Return Code             | Semantics                                       |
| :---------------------- | :---------------------------------------------- |
| `EFI_SUCCESS`           | Operation is successful.                        |
| `EFI_INVALID_PARAMETER` | One of `Self` or `GetVarAllCallback` is `NULL`. |

## GBL_EFI_FASTBOOT_PROTOCOL.GetStaged()

### Summary

Reads OEM-provided payload for uploading to the host during the
`fastboot get_staged` command.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_FASTBOOT_GET_STAGED)(
  IN GBL_EFI_FASTBOOT_PROTOCOL *Self,
  IN OUT UINTN                 *BufferSize,
  OUT UINTN                    *BufferRemains,
  OUT UINT8                    *Buffer
  );
```

### Parameters

#### Self

A pointer to the `GBL_EFI_FASTBOOT_PROTOCOL` instance.

#### BufferSize

On input, stores the size of the output buffer `Buffer`. On output, stores the
actual number of bytes read to `Buffer`.

#### BufferRemains

On output, stores the number of remaining bytes left to read.

#### Buffer

Pointer to the output buffer.

### Description

`GetStaged()` reads OEM defined data for uploading to fastboot host during
command `fastboot get_staged`. The function may be called multiple times to read
out the whole payload in chunks to accommodate callers with limited buffer.
Implementation should internally track read progress and avoid changing the
backing data when caller starts reading. However, outside the session of
`fastboot get_staged`, i.e. when in `CommandExec`, implementation can change or
update the backing data.

Caller may pass a 0-length input buffer for peeking the total via
`BufferRemains`. This should be expected by the implementation.

The typical usage is for the vendor to provide an OEM command that sets up the
payload and then retrieve the payload via `fastboot get_staged` from the host.

### Status Codes Returned

| Return Code             | Semantics                                                 |
| :---------------------- | :-------------------------------------------------------- |
| `EFI_SUCCESS`           | The call completed successfully.                          |
| `EFI_INVALID_PARAMETER` | Any of `BufferSize`, `BufferRemains`, `Buffer` is `NULL`. |
| `EFI_ACCESS_DENIED`     | The operation is not permitted in the current lock state. |

## GBL_EFI_FASTBOOT_PROTOCOL.CommandExec()

### Summary

Allows for command filtering and implementation override.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_FASTBOOT_COMMAND_EXEC)(
  IN GBL_EFI_FASTBOOT_PROTOCOL             *Self,
  IN UINTN                                 NumArgs,
  IN CONST CHAR8 * CONST                   *Args,
  IN UINTN                                 DownloadBufferSize,
  IN UINTN                                 DownloadBufferUsedSize,
  IN UINT8                                 *DownloadBuffer,
  OUT GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT *Implementation,
  IN FASTBOOT_MESSAGE_SENDER               Sender,
  IN VOID                                  *Context
  );
```

### Parameters

#### Self

A pointer to the `GBL_EFI_FASTBOOT_PROTOCOL` instance.

#### NumArgs

The number of elements in the `Args` array.

#### Args

A pointer to an array of null-terminated UTF-8 strings that contains the
Fastboot command followed by additional arguments.

#### DownloadBufferSize

Full size of the download data buffer `DownloadBuffer`. It can be larger than
`DownloadBufferUsedSize` for custom implementation use.

#### DownloadBufferUsedSize

The size of the download data in `DownloadBuffer`.

#### DownloadBuffer

A pointer to the most recent downloaded data.

`DownloadBuffer` along with `DownloadBufferSize` and `DownloadBufferUsedSize`
provide additional context for commands such as `fastboot flash`.

#### Implementation

On exit, set to one of the values:

- `GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_PROHIBITED` - indicates that command is
  not allowed. GBL is responsible for communicating the prohibition to the user.
  This is a convenience common case and GBL will send a generic error message. A
  custom error message can be sent if the exec result is
  `GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_CUSTOM_IMPL`.
- `GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_DEFAULT_IMPL` - GBL will use its own
  default implementation to handle the command.
- `GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_CUSTOM_IMPL` - command is handled by
  running custom implementation. Vendor firmware is responsible for guaranteeing
  that the implementation has run to completion before returning this value. GBL
  will ignore the command assuming it has been handled.

#### Sender

A pointer to a function of type `FASTBOOT_MESSAGE_SENDER`. The function is used
by the implementation to send custom Fastboot `OKAY`/`FAIL`/`INFO` messages. For
input arguments, it takes the `Context` pointer passed to this function, the
message type, the string length, and a pointer to a UTF-8 string.

Warning: The `Sender` parameter should only be used for commands that are
`CUSTOM_IMPL`. Using `Sender` to send messages for commands that are
`PROHIBITED` or `DEFAULT_IMPL` will result in undefined behavior, incorrect
output, or will leave the Fastboot protocol in a bad state.

`OKAY`/`FAIL` messages should only be sent once. Sending more than one `OKAY` or
`FAIL` or sending both may break the Fastboot exchange sequence. It is the
caller's responsibility to provide a sender function that verifies that at most
one `OKAY` or `FAIL` message is sent and returns `EFI_PROTOCOL_ERROR` if the
implementation violates this requirement.

Likewise, if the implementation returns without sending any `OKAY`/`FAIL`
message, the caller should send either an `OKAY` or a `FAIL` based on the return
value of this API.

#### Context

A pointer to the context data for `Sender`.

### Description

`CommandExec()` queries whether a fastboot command is allowed and what
implementation to use.

It's up to the caller to decide how to proceed in the case of error, i.e base on
the level of security requirement.

If "default implementation" is requested GBL will handle the command using an
implementation within GBL.

If "custom implementation" is indicated GBL will assume that the callee handled
the command; for `flash` and `erase` commands, GBL then best-effort re-reads GPT
partition tables across existing GPT block devices (`EFI_BLOCK_IO_MEDIA`
geometry remains cached from boot).

The following commands cannot be overridden with
`GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_CUSTOM_IMPL` (they are still passed to
`CommandExec()` and may only return
`GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_DEFAULT_IMPL` or
`GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_PROHIBITED`):

<!-- LINT.IfChange -->

- `continue`
- `download`
- `fetch`
- `getvar`
- `reboot`
- `reboot-bootloader`
- `reboot-fastboot`
- `reboot-recovery`
- `set_active`
- `upload`
<!-- LINT.ThenChange(/gbl/libfastboot/src/lib.rs) -->

### Status Codes Returned

| Return Code             | Semantics                                                                                                                                  |
| :---------------------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| `EFI_SUCCESS`           | The call completed successfully.                                                                                                           |
| `EFI_INVALID_PARAMETER` | One of `Args`, `Implementation` is `NULL`. Or `DownloadBuffer` is `NULL` but `DownloadBufferSize` or `DownloadBufferUsedSize` is non-zero. |
| `EFI_DEVICE_ERROR`      | An internal error occurred.                                                                                                                |

### Related Definitions

#### GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT

```c
enum {
  GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_PROHIBITED,
  GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_DEFAULT_IMPL,
  GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT_CUSTOM_IMPL,
};

typedef UINT32 GBL_EFI_FASTBOOT_COMMAND_EXEC_RESULT;
```

#### GBL_EFI_FASTBOOT_MESSAGE_TYPE

```c
enum {
  GBL_EFI_FASTBOOT_MESSAGE_TYPE_OKAY,
  GBL_EFI_FASTBOOT_MESSAGE_TYPE_FAIL,
  GBL_EFI_FASTBOOT_MESSAGE_TYPE_INFO,
};

typedef UINT32 GBL_EFI_FASTBOOT_MESSAGE_TYPE;
```

#### FASTBOOT_MESSAGE_SENDER

```c
typedef
EFI_STATUS
(*FASTBOOT_MESSAGE_SENDER)(
  IN VOID                          *Context,
  IN GBL_EFI_FASTBOOT_MESSAGE_TYPE MsgType,
  IN UINTN                         MsgLen,
  IN CONST CHAR8                   *Msg
  );
```

##### Context

The pointer to the context passed to `CommandExec()`.

##### MsgType

A `GBL_EFI_FASTBOOT_MESSAGE_TYPE` value indicating the message type.

##### MsgLen

The length of `Msg`.

##### Msg

A pointer to a UTF-8 string. The string does not need to be null-terminated.

Note: The maximum allowed length of a message depends on the transport. For
example, for Fastboot over USB, it is the native packet size. The implementation
should consider the transport setup it provides when passing the string.
Oversized messages may be truncated by the caller when sent to the host.

## GBL_EFI_FASTBOOT_PROTOCOL.GetPartitionType()

### Summary

Gets the type of partition.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_FASTBOOT_GET_PARTITION_TYPE)(
  IN GBL_EFI_FASTBOOT_PROTOCOL *Self,
  IN CONST CHAR8               *PartName,
  IN OUT UINTN                 *PartTypeLen,
  OUT CHAR8                    *PartType
  );
```

### Related Definitions

#### GBL_EFI_FASTBOOT_PARTITION_TYPE_BUF_LEN

```c
static const UINTN GBL_EFI_FASTBOOT_PARTITION_TYPE_BUF_LEN = 56;
```

### Parameters

#### Self

A pointer to the `GBL_EFI_FASTBOOT_PROTOCOL` instance.

#### PartName

The null-terminated name of the partition to query.

#### PartTypeLen

On entry, the size of the `PartType` buffer. This should be larger than or equal
to `GBL_EFI_FASTBOOT_PARTITION_TYPE_BUF_LEN`.

On exit, the size in bytes of the `PartType` string, excluding any
null-terminator.

#### PartType

A buffer to write the result to. This does not need to be null-terminated.

### Description

This API is for supporting `fastboot format`. The partition type returned here
would be reported to the fastboot client in `getvar partition-type:<partname>`.

If the partition should support formatting with `fastboot format`, then
`PartType` should contain the filesystem type to format to.

If a partition or all partitions shouldn't support `fastboot format`, then this
API can be left unimplemented or return `EFI_UNSUPPORTED`. In that case GBL
reports the partition type as `raw`.

### Status Codes Returned

| Return Code             | Semantics                                                                                                                              |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------- |
| `EFI_SUCCESS`           | The call completed successfully.                                                                                                       |
| `EFI_INVALID_PARAMETER` | One of `Self`, `PartName`, `PartType`, or `PartTypeLen` is `NULL`.                                                                     |
| `EFI_UNSUPPORTED`       | `PartName` is a raw partition that doesn't support `fastboot format`.                                                                  |
| `EFI_BUFFER_TOO_SMALL`  | `PartType` buffer is too small to store the result. The value of `PartTypeLen` should be updated to the minimum necessary buffer size. |

[get_var]: #gbl_efi_fastboot_protocol_getvar
[get_var_all]: #gbl_efi_fastboot_protocol_getvarall
[get_staged]: #gbl_efi_fastboot_protocol_getstaged
[command_exec]: #gbl_efi_fastboot_protocol_commandexec
[get_partition_type]: #gbl_efi_fastboot_protocol_getpartitiontype
[custom_protocol_revisions]: efi_integration.md#gbl-custom-protocol-revisions
