#ifndef _GKUT2FS_H_
#define _GKUT2FS_H_

#include <efi.h>
#include <Protocol/SimpleFileSystem.h>

EFI_STATUS gkut2_efi_open_volume();

EFI_STATUS gkut2_efi_file_size(EFI_FILE_HANDLE FileHandle, UINT64 *FileSize);

EFI_STATUS gkut2_efi_read_file(CHAR16 *FileName, UINT64 MaxFileSize, UINT8 **Buffer_freeme_out);

#endif
