#ifndef _GKUT2FS_H_
#define _GKUT2FS_H_

#include <efi.h>
#include <efiprot.h>

EFI_STATUS gkut2_efi_open_volume();

EFI_STATUS gkut2_efi_close_volume();

EFI_STATUS gkut2_efi_file_size(EFI_FILE_HANDLE FileHandle, UINT64 *FileSize);

EFI_STATUS gkut2_efi_read_file(CHAR16 *FileName, UINT64 *FileSize, UINT8 *Buffer, UINT64 Offset);

#endif
