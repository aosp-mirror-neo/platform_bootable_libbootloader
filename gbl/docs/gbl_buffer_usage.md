# Buffer Usage in GBL

This doc discusses memory buffer usage by GBL.

## Boot Buffers

At run time, GBL requests the following memory buffers via
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()][get_boot_buffer] for assembling
various boot images such as kernel, ramdisk, FDT and pvmfw.

### General Load Buffer

GBL uses this buffer for:

1. Passing fastboot boot items (command line and bootconfig additions).
2. Temporary scratch buffers for reading BCB boot mode etc.
3. Relocating DT components that are not 8-byte aligned (from the dtb and dtbo
   partitions and boot image DTB sections). The buffer should fit all of them.

GBL queries the buffer by calling
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()][get_boot_buffer] with parameter
`BootBufferType` set to `GENERAL_LOAD`. If buffer is not provided, GBL allocates
a default 16MB memory via EFI allocation.

### Kernel Load Buffer

GBL uses this buffer for placing the kernel image (after decompression) from the
Android Boot image. This will also be the buffer GBL boots OS from. On aarch64
and riscv64, the buffer must be at least the kernel header's `image_size`, which
includes BSS.

GBL queries the buffer by calling
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()][get_boot_buffer] with parameter
`BootBufferType` set to `KERNEL`. If buffer is not provided, GBL allocates a
default 128MB memory via EFI allocation.

### Ramdisk Load Buffer

GBL uses this buffer for assembling ramdisk image and bootconfig (including
fastboot bootconfig additions) for boot.

GBL queries the buffer by calling
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()][get_boot_buffer] with parameter
`BootBufferType` set to `RAMDISK`. If buffer is not provided, GBL allocates a
default 96MB memory via EFI allocation.

### FDT Load Buffer

GBL uses this buffer for constructing and fixing up the final FDT for boot.

GBL queries the buffer by calling
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()][get_boot_buffer] with parameter
`BootBufferType` set to `FDT`. If buffer is not provided, GBL allocates a
default 4MB memory via EFI allocation.

### Pvmfw Load Buffer

GBL uses this buffer for assembling the pvmfw image.

GBL queries the buffer only when it loads pvmfw, which requires
[GBL_EFI_AVF_PROTOCOL][gbl_avf_protocol] and a `pvmfw` partition. It calls
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()][get_boot_buffer] with parameter
`BootBufferType` set to `PVMFW_DATA`. If buffer is not provided, GBL allocates a
default 16MB memory via EFI allocation.

### Fastboot Download Buffer

GBL uses this buffer as download buffer in fastboot mode.

GBL queries the buffer by calling
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetBootBuffer()][get_boot_buffer] with parameter
`BootBufferType` set to `FASTBOOT_DOWNLOAD`. If the buffer is not provided, GBL
allocates a default 512MB memory via EFI allocation.

## Partition Read Buffers

By default, GBL allocates memory for reading disk partitions when assembling
boot images. Firmware can override this for individual partitions by providing a
dedicated read buffer via the
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetPartitionBuffer()][get_partition_buffer] API.
Before reading a partition, GBL queries the buffer using the slotless partition
name. For example, before reading `"boot_a/b"` partition, GBL calls
[GBL_EFI_BOOT_MEMORY_PROTOCOL.GetPartitionBuffer()][get_partition_buffer] with
parameter `BaseName` set to `"boot"`.

Firmware can also provide preloaded partition data in the buffer. The
`PRELOADED` bit in the output parameter `Flag` should be set in this case. GBL
skips reading the partition when preloaded data is available. This can be used
for optimizing boot performance or overriding target boot images (images still
need to pass AVB verification in locked mode).

If GBL has entered fastboot mode in the same session, preloaded partition data
may be outdated since new images may have been flashed and active slot may have
been changed. In this case, GBL calls
[GBL_EFI_BOOT_MEMORY_PROTOCOL.SyncPartitionBuffer()][sync_partition_buffer] with
parameter `SyncPreloaded` set to true after exiting fastboot mode and before
querying any partition buffer. Firmware should either reload the partitions, or
simply clear the `PRELOADED` bit to instruct GBL to read from disk by itself.

After GBL finishes assembling kernel/ramdisk/FDT from partition images, and
before fixing up FDT/bootconfig via
[GBL_EFI_OS_CONFIGURATION_PROTOCOL][gbl_os_configuration_protocol], GBL calls
[GBL_EFI_BOOT_MEMORY_PROTOCOL.SyncPartitionBuffer()][sync_partition_buffer] with
parameter `SyncPreloaded` set to false. Firmware can take this chance to inspect
newly loaded images in the provided partition buffers and determines the needed
FDT/bootconfig fixup if needed.

The following summarizes the order of events discussed above.

1. If GBL previously entered fastboot, calls
   [GBL_EFI_BOOT_MEMORY_PROTOCOL.SyncPartitionBuffer(SyncPreloaded=TRUE)][sync_partition_buffer]
2. Queries partition buffer with
   [GBL_EFI_BOOT_MEMORY_PROTOCOL.GetPartitionBuffer()][get_partition_buffer].
3. Reads, verifies partition images and assembles kernel/ramdisk/FDT.
4. Calls
   [GBL_EFI_BOOT_MEMORY_PROTOCOL.SyncPartitionBuffer(SyncPreloaded=FALSE)][sync_partition_buffer].
5. Fixes up FDT and bootconfig via DT_FIXUP and
   [GBL_EFI_OS_CONFIGURATION_PROTOCOL][gbl_os_configuration_protocol].
6. Boot.

## AARCH64 Kernel Decompression

GBL can detect and handle compressed kernel for aarch64. However, current
implementation requires allocating a separate piece of memory for storing
decompressed kernel temporarily. This buffer is allocated via EFI memory
allocation.

## AVB

The AVB (Android Verified Boot) implementation in GBL requires allocating
additional memory for constructing commandline argument strings and loading
vbmeta images from disk and any other vendor required partitions for
verification. The memory is allocated via EFI memory allocation.

[get_boot_buffer]:
  ./gbl_efi_boot_memory_protocol.md#gbl_efi_boot_memory_protocol_getbootbuffer
[get_partition_buffer]:
  ./gbl_efi_boot_memory_protocol.md#gbl_efi_boot_memory_protocol_getpartitionbuffer
[sync_partition_buffer]:
  ./gbl_efi_boot_memory_protocol.md#gbl_efi_boot_memory_protocol_syncpartitionbuffer
[gbl_os_configuration_protocol]: ./gbl_efi_os_configuration_protocol.md
[gbl_avf_protocol]: ./gbl_efi_avf_protocol.md
