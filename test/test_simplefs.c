#include <stdio.h>
#include <efi.h>
#include <efiprot.h>
#include <assert.h>

#include "gkut2fs.h"

void mock_simplefs_init();

extern EFI_LOADED_IMAGE *boot_img; // in stand's main.c

static EFI_FILE_IO_INTERFACE *Volume;
static EFI_FILE_HANDLE Fs;

void test_01_openvolume() {
    printf("======= test_01_openvolume() =======\n");
    EFI_GUID Guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    printf("BS->HandleProtocol: 0x%08X\n", BS->HandleProtocol);
    printf("boot_img: 0x%08X\n", boot_img);
    EFI_STATUS Status;
    Status = BS->HandleProtocol(boot_img->DeviceHandle, &Guid, (void**) &Volume);
    assert(Status == EFI_SUCCESS);
    Status = Volume->OpenVolume(Volume, &Fs);
    assert(Status == EFI_SUCCESS);
    Status = Fs->Close(Fs);
    assert(Status == EFI_SUCCESS);
    printf("Success!!!\n");
}

void test_02_file_open() {
    printf("======== test_02_file_open() ========\n");
    EFI_GUID Guid = SIMPLE_FILE_SYSTEM_PROTOCOL;
    EFI_STATUS Status;
    Status = BS->HandleProtocol(boot_img->DeviceHandle, &Guid, (void**) &Volume);
    assert(Status == EFI_SUCCESS);
    Status = Volume->OpenVolume(Volume, &Fs);
    assert(Status == EFI_SUCCESS);
    EFI_FILE_HANDLE File;
    Status = Fs->Open(Fs, &File, u"/efi/freebsd/test.txt", EFI_FILE_MODE_READ, 0); 
    assert(Status == EFI_SUCCESS);
    Status = File->Close(File);
    assert(Status == EFI_SUCCESS);
    printf("Success!!!\n");
}

void test03_gkut2_efi_open_volume() {
    printf("======= test03_gkut2_efi_open_volume() =======\n");
    EFI_STATUS Status;
    Status = gkut2_efi_open_volume();
    assert(Status == EFI_SUCCESS);
    Status = gkut2_efi_close_volume();
    assert(Status == EFI_SUCCESS);
    printf("Success!!!\n");
}

void test04_gkut2_efi_file_read() {
    printf("======= test04_gkut2_efi_file_read() =======\n");
    EFI_STATUS Status;
    Status = gkut2_efi_open_volume();
    assert(Status == EFI_SUCCESS);
    UINT8 Buffer[1024];
    UINT64 FileSize = 1024;
    Status = gkut2_efi_read_file(u"/efi/freebsd/test.txt", &FileSize, &Buffer[0], 0);
    assert(Status == EFI_SUCCESS);
    printf("FileSize: %llu\n", FileSize);
    UINT8 *p = &Buffer[0];
    while (*p) {
        printf("%02X ", *p);
        p++;
    }
    printf("\n");
    assert(Status == EFI_SUCCESS);
    printf("Buffer_freeme: %s\n", &Buffer[0]);
    Status = gkut2_efi_close_volume();
    assert(Status == EFI_SUCCESS);
    printf("Success!!!\n");
}

int main() {
    mock_simplefs_init();
    test_01_openvolume();
    test_02_file_open();
    test03_gkut2_efi_open_volume();
    test04_gkut2_efi_file_read();
}

