/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2022 Stanislaw R. Adaszewski
 * All rights reserved.
 *
 *	@(#)tpm2fs.c	13.0 (Villeneuve) 10/30/22
 */

#include <efi.h>
#include <efilib.h>
#include <efichar.h>
#include <efiprot.h>

extern EFI_LOADED_IMAGE *boot_img; // in stand's main.c


static EFI_GUID mSimpleFileSystemProtocolGuid = SIMPLE_FILE_SYSTEM_PROTOCOL;
EFI_FILE_IO_INTERFACE *mIOVolume;
EFI_FILE_HANDLE mVolume = NULL;


// GELI Key Using TPM2 = GKUT2

EFI_STATUS gkut2_efi_open_volume() {
    EFI_STATUS Status;

    if (mIOVolume == NULL) {
		Status = BS->HandleProtocol(boot_img->DeviceHandle,
            &mSimpleFileSystemProtocolGuid,
            (VOID **) &mIOVolume);

		if (EFI_ERROR (Status)) {
			//
			// Simple file system protocol is not installed.
			//
			printf("gkut2_efi_open_volume() - HandleProtocol() - %lu\n", Status);
			return Status;
		}
	}

	if (mVolume == NULL) {
        Status = mIOVolume->OpenVolume(mIOVolume, &mVolume);

        if (EFI_ERROR (Status)) {
			//
			// Cannot open volume.
			//
			printf("gkut2_efi_open_volume() - OpenVolume() - %lu\n", Status);
			return Status;
		}
    }

    return EFI_SUCCESS;
}

EFI_STATUS gkut2_efi_file_size(EFI_FILE_HANDLE FileHandle, UINT64 *FileSize) {
    UINTN BufferSize = sizeof(EFI_FILE_INFO);
    EFI_STATUS Status;
    EFI_FILE_INFO Buffer;
    EFI_GUID FileInfoIdGuid = EFI_FILE_INFO_ID;

    Status = FileHandle->GetInfo(FileHandle,
        &FileInfoIdGuid,
        &BufferSize,
        &Buffer);

    if (EFI_ERROR(Status)) {
        printf("gkut2_efi_file_size() - GetInfo() - %lu\n", Status);
        return Status;
    }

    *FileSize = Buffer.FileSize;

    return EFI_SUCCESS;
}


EFI_STATUS gkut2_efi_read_file(CHAR16 *FileName, UINT64 MaxFileSize, UINT8 **Buffer_freeme_out) {
    EFI_STATUS Status;
    EFI_FILE_HANDLE FileHandle;
    UINT64 FileSize;
    UINT8 *Buffer_freeme = NULL;

    *Buffer_freeme_out = NULL;

    Status = gkut2_efi_open_volume();
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = mVolume->Open(mVolume, &FileHandle, FileName,
        EFI_FILE_MODE_READ,
        EFI_FILE_READ_ONLY | EFI_FILE_HIDDEN | EFI_FILE_SYSTEM);
    if (EFI_ERROR(Status)) {
        printf("gkut2_efi_read_file() - mVolume->Open() - %lu\n", Status);
        return Status;
    }

    Status = gkut2_efi_file_size(FileHandle, &FileSize);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    if (FileSize > MaxFileSize) {
        printf("gkut2_efi_read_file() - file too large\n");
        return EFI_BAD_BUFFER_SIZE;
    }

    Buffer_freeme = (UINT8*) malloc(FileSize);
    Status = FileHandle->Read(FileHandle, &FileSize, Buffer_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_efi_read_file() - Read() - %lu\n", Status);
        (void)free(Buffer_freeme);
        return Status;
    }

    Status = FileHandle->Close(FileHandle);
    if (EFI_ERROR(Status)) {
        printf("gkut2_efi_read_file() - Close() - %lu\n", Status);
        (void)free(Buffer_freeme);
        return Status;
    }

    *Buffer_freeme_out = Buffer_freeme;
    return EFI_SUCCESS;
}
