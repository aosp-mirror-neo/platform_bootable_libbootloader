# GBL EFI Boot Memory Protocol

|                |            |
| :------------- | :--------- |
| **Status**     | Stable     |
| **Created**    | 2025-07-13 |
| **Stabilized** | 2026-05-22 |

## GBL_EFI_BOOT_MEMORY_PROTOCOL

### Summary

The GBL Boot Memory protocol allows UEFI firmware to provide reserved buffers
for sharing preloaded partition images with GBL, or as destination buffers for
GBL to load images, assemble kernel/ramdisk/FDT images, and download data in
Fastboot mode.

### GUID

```c
// {309f2874-ad59-4fd2-af5e-ce0f4ab401a6}
#define GBL_EFI_BOOT_MEMORY_PROTOCOL_GUID            \
  {                                                  \
    0x309f2874, 0xad59, 0x4fd2, {                    \
      0xaf, 0x5e, 0xce, 0x0f, 0x4a, 0xb4, 0x01, 0xa6 \
    }                                                \
  }
```

### Revision Number

```c
#define GBL_EFI_BOOT_MEMORY_PROTOCOL_REVISION GBL_PROTOCOL_REVISION(1, 0)
```

See [GBL Custom Protocol Revisions][custom_protocol_revisions] for details about
protocol revisions.

### Protocol Interface Structure

```c
typedef struct _GBL_EFI_BOOT_MEMORY_PROTOCOL {
  UINT64                        Revision;
  GBL_EFI_GET_PARTITION_BUFFER  GetPartitionBuffer;
  GBL_EFI_SYNC_PARTITION_BUFFER SyncPartitionBuffer;
  GBL_EFI_GET_BOOT_BUFFER       GetBootBuffer;
} GBL_EFI_BOOT_MEMORY_PROTOCOL;
```

### Parameters

#### Revision

The revision to which the `GBL_EFI_BOOT_MEMORY_PROTOCOL` adheres. All future
revisions must be backwards compatible. If a future version is not backwards
compatible, a different GUID must be used.

#### GetPartitionBuffer

Retrieves the reserved memory for loading a specific partition image. See
[`GetPartitionBuffer()`][get_partition_buffer] for more information.

#### SyncPartitionBuffer

Notifies the firmware to inspect or update all reserved buffers returned by
`GetPartitionBuffer()`. See [`SyncPartitionBuffer()`][sync_partition_buffer] for
more information.

#### GetBootBuffer

Retrieves the reserved memory for assembling various boot images. See
[`GetBootBuffer()`][get_boot_buffer] for more information.

## GBL_EFI_BOOT_MEMORY_PROTOCOL.GetPartitionBuffer()

### Summary

Gets the reserved buffer for loading a partition image.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_GET_PARTITION_BUFFER)(
  IN GBL_EFI_BOOT_MEMORY_PROTOCOL   *Self,
  IN CONST CHAR8                    *BaseName,
  OUT UINTN                         *Size,
  OUT VOID                          **Addr,
  OUT GBL_EFI_PARTITION_BUFFER_FLAG *Flag
  );
```

### Parameters

#### Self

A pointer to the `GBL_EFI_BOOT_MEMORY_PROTOCOL` instance.

#### BaseName

A null-terminated UTF-8 encoded string representing the slotless partition name.

#### Size

An output parameter to store the size of the reserved memory in bytes.

#### Addr

An output parameter to store the address of the reserved memory.

#### Flag

An output parameter to store flags containing additional information about the
memory. See [GBL_EFI_PARTITION_BUFFER_FLAG][partition_buffer_flag] for more
details.

### Description

This interface is optional and can be used by the firmware to provide designated
buffers for the bootloader to read various images. The firmware can also preload
images into memory and share them with the bootloader via this interface. In
this case, the `GBL_EFI_PARTITION_BUFFER_FLAG_PRELOADED` bit must be set in
`Flag`. If no memory is provided, GBL is responsible for finding the required
memory.

Firmware must guarantee that preloaded data is up-to-date when this API is
called. Each partition image must map to a unique reserved memory that remains
valid for read and write operations throughout the lifetime of the GBL
application. It is up to GBL to interpret and validate the content in the memory
before use.

Certain partition images have specific alignment requirements. For example,
DTB/DTBO images must be loaded into 8-byte aligned buffers. Failure to meet
these requirements may cause GBL to process the image data incorrectly. Thus,
firmware should ensure it provides correctly aligned memory that matches the
requirements of the image. For alignment requirements on common boot images, see
[`GetBootBuffer()`][get_boot_buffer].

Note: Each device-specific partition that requests verification in
[`GBL_EFI_AVB_PROTOCOL.ReadPartitionAttributes()`][avbreadpartitionattributes]
can provide a partition buffer using the same partition name.

### Related Definitions

#### GBL_EFI_PARTITION_BUFFER_FLAG

```c
enum {
  GBL_EFI_PARTITION_BUFFER_FLAG_PRELOADED = 1 << 0,
};

typedef UINT32 GBL_EFI_PARTITION_BUFFER_FLAG;
```

##### PRELOADED

If set, it indicates the buffer returned by `GetPartitionBuffer()` already
contains the image loaded by the firmware.

### Status Codes Returned

| Return Code             | Semantics                                                         |
| :---------------------- | :---------------------------------------------------------------- |
| `EFI_SUCCESS`           | The buffer was provided successfully.                             |
| `EFI_NOT_FOUND`         | The platform does not have reserved memory for this image.        |
| `EFI_INVALID_PARAMETER` | `Self` is invalid, or any of `Addr`, `Size`, or `Flag` is `NULL`. |

## GBL_EFI_BOOT_MEMORY_PROTOCOL.SyncPartitionBuffer()

### Summary

Notifies the firmware to inspect or update buffers returned by
`GetPartitionBuffer()`.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_SYNC_PARTITION_BUFFER)(
  IN GBL_EFI_BOOT_MEMORY_PROTOCOL *Self,
  IN BOOLEAN                      SyncPreloaded
  );
```

### Parameters

#### Self

A pointer to the `GBL_EFI_BOOT_MEMORY_PROTOCOL` instance.

#### SyncPreloaded

Set to true to instruct the firmware to sync preloaded partition data based on
the current device state.

### Description

Caller calls this interface to allow the firmware to inspect, update, or move
the buffers returned by `GetPartitionBuffer()`. Caller can call this API after
loading new images into the buffers to notify the firmware to process them.

Caller can also call this API with `SyncPreloaded` set to true to request the
firmware to re-sync preloaded partition data. Firmware should either re-load the
partitions if supported, or invalidate existing ones by clearing the `PRELOADED`
bit or returning `EFI_NOT_FOUND` for future calls to `GetPartitionBuffer()`.

After calling this method, all buffers previously obtained from
`GetPartitionBuffer()` must be considered invalid.

### Status Codes Returned

| Return Code             | Semantics                    |
| :---------------------- | :--------------------------- |
| `EFI_SUCCESS`           | Sync completed successfully. |
| `EFI_DEVICE_ERROR`      | An internal error occurred.  |
| `EFI_INVALID_PARAMETER` | `Self` is invalid.           |

### Examples

Below is an example of how a bootloader application interacts with
firmware-provided partition buffers using this API.

```c
GBL_EFI_BOOT_MEMORY_PROTOCOL  *Protocol;
BOOLEAN                       DiskContentChanged;
EFI_STATUS                    Status;

// Ensure partition buffers are up-to-date
Status = Protocol->SyncPartitionBuffer(Protocol, DiskContentChanged);

// Interact with partition buffers
Status = Protocol->GetPartitionBuffer(Protocol, "boot", ...);
...
// Notify firmware that new images may have been loaded
Status = Protocol->SyncPartitionBuffer(Protocol, FALSE);
...
// Boot OS
```

## GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()

### Summary

Gets the reserved buffers for the bootloader to construct boot images.

### Prototype

```c
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_GET_BOOT_BUFFER)(
  IN GBL_EFI_BOOT_MEMORY_PROTOCOL *Self,
  IN GBL_EFI_BOOT_BUFFER_TYPE     BootBufferType,
  OUT UINTN                       *Size,
  OUT VOID                        **Addr
  );
```

### Parameters

#### Self

A pointer to the `GBL_EFI_BOOT_MEMORY_PROTOCOL` instance.

#### BootBufferType

A `GBL_EFI_BOOT_BUFFER_TYPE` value that identifies the type of boot buffer.

#### Size

An output parameter to store the size of the reserved memory if available, or
the recommended size for GBL to allocate.

#### Addr

An output parameter to store the address of the reserved memory if available, or
`NULL` to indicate that GBL should allocate its own memory.

### Description

This interface can be used by the firmware to provide designated buffers for GBL
to assemble various boot images (kernel, ramdisk, FDT, pvmfw, etc.) or download
data in Fastboot.

If no memory is provided, GBL determines where to find the required memory.

In some cases, the firmware may choose not to reserve memory but instead
recommend that GBL allocate it at runtime. In this case, `Addr` should be set to
`NULL` and `Size` to the recommended allocation size. This is useful for buffers
like the Fastboot download buffer, which is only needed on demand. If `Addr` is
`NULL` and `Size` is 0, GBL handles it like `EFI_NOT_FOUND`.

### Related Definitions

#### GBL_EFI_BOOT_BUFFER_TYPE

```c
enum {
  GBL_EFI_BOOT_BUFFER_TYPE_GENERAL_LOAD,
  GBL_EFI_BOOT_BUFFER_TYPE_KERNEL,
  GBL_EFI_BOOT_BUFFER_TYPE_RAMDISK,
  GBL_EFI_BOOT_BUFFER_TYPE_FDT,
  GBL_EFI_BOOT_BUFFER_TYPE_PVMFW_DATA,
  GBL_EFI_BOOT_BUFFER_TYPE_FASTBOOT_DOWNLOAD,
};

typedef UINT32 GBL_EFI_BOOT_BUFFER_TYPE;
```

##### GBL_EFI_BOOT_BUFFER_TYPE_GENERAL_LOAD

General-purpose load buffer. Used for scratch data, for example:

- Passing fastboot boot items (command line and bootconfig additions).
- Reading and updating the bootloader message (BCB) in the `misc` partition.
- Relocating DT components that are not 8-byte aligned.

##### GBL_EFI_BOOT_BUFFER_TYPE_KERNEL

Memory for assembling the finalized kernel. Must be 2MB aligned.

##### GBL_EFI_BOOT_BUFFER_TYPE_RAMDISK

Memory for assembling the finalized ramdisk.

##### GBL_EFI_BOOT_BUFFER_TYPE_FDT

Memory for assembling the finalized FDT. Must be 8-byte aligned.

##### GBL_EFI_BOOT_BUFFER_TYPE_PVMFW_DATA

Memory for loading finalized protected VM firmware. The address must be aligned
to the page size used by the hypervisor (typically 4KB or 16KB depending on
kernel configuration).

##### GBL_EFI_BOOT_BUFFER_TYPE_FASTBOOT_DOWNLOAD

Memory for use as the download buffer in Fastboot mode.

### Status Codes Returned

| Return Code             | Semantics                                                                                |
| :---------------------- | :--------------------------------------------------------------------------------------- |
| `EFI_SUCCESS`           | The buffer was provided successfully.                                                    |
| `EFI_NOT_FOUND`         | The platform does not have reserved memory or a suggested allocation size for this type. |
| `EFI_INVALID_PARAMETER` | `Self` is invalid, or either `Addr` or `Size` is `NULL`.                                 |

[get_partition_buffer]: #gbl_efi_boot_memory_protocol_getpartitionbuffer
[sync_partition_buffer]: #gbl_efi_boot_memory_protocol_syncpartitionbuffer
[get_boot_buffer]: #gbl_efi_boot_memory_protocol_getbootbuffer
[custom_protocol_revisions]: efi_integration.md#gbl-custom-protocol-revisions
[partition_buffer_flag]: #gbl_efi_partition_buffer_flag
[avbreadpartitionattributes]:
  ./gbl_efi_avb_protocol.md#gbl_efi_avb_protocol_readpartitionattributes
