
#include <efi.h>
#include <efiprot.h>

#include <stdlib.h>

#define MOCKFS_PREFIX "/tmp/mock-simplefs/"

EFI_LOADED_IMAGE boot_img_ = {};

EFI_LOADED_IMAGE *boot_img = &boot_img_;

static EFI_STATUS DummyClose (
    IN struct _EFI_FILE_HANDLE  *File);

static EFI_STATUS DummyRead (
    IN struct _EFI_FILE_HANDLE  *File,
    IN OUT UINTN                *BufferSize,
    OUT VOID                    *Buffer);

static EFI_STATUS DummyGetInfo(
    IN struct _EFI_FILE_HANDLE  *File,
    IN EFI_GUID                 *InformationType,
    IN OUT UINTN                *BufferSize,
    OUT VOID                    *Buffer
    );

static EFI_STATUS DummyOpen (
    IN struct _EFI_FILE_HANDLE  *File,
    OUT struct _EFI_FILE_HANDLE **NewHandle,
    IN CHAR16                   *FileName,
    IN UINT64                   OpenMode,
    IN UINT64                   Attributes) {

    if (File->FileObj != NULL) {
        printf("DummyOpen() - Trying to open file from file, use volume instead\n");
        return EFI_UNSUPPORTED;
    }

    int FileNameLen = 0;
    while(FileName[FileNameLen] != 0) 
        FileNameLen++;
    char *FileNameMB = (char*) malloc(FileNameLen + 1);
    for (int i = 0; i < FileNameLen; i++) {
        FileNameMB[i] = FileName[i];
    }
    FileNameMB[FileNameLen] = 0;
    char *FileNameFinal = (char*) malloc(FileNameLen + strlen(MOCKFS_PREFIX) + 1);
    FileNameFinal[0] = 0;
    strcat(FileNameFinal, MOCKFS_PREFIX);
    strcat(FileNameFinal, FileNameMB);
    (void)free(FileNameMB);

    FILE *FileObj = fopen(FileNameFinal, "rb");
    if (FileObj == NULL) {
        printf("DummyOpen() - Failed to open %s\n", FileNameFinal);
        (void)free(FileNameFinal);
        return EFI_NOT_FOUND;
    }
    (void)free(FileNameFinal);

    *NewHandle = (EFI_FILE_HANDLE) malloc(sizeof(EFI_FILE));
    (*NewHandle)->Open = DummyOpen;
    (*NewHandle)->Close = DummyClose;
    (*NewHandle)->Read = DummyRead;
    (*NewHandle)->GetInfo = DummyGetInfo;
    (*NewHandle)->FileObj = FileObj;

    return EFI_SUCCESS;
}

static EFI_STATUS DummyClose (
    IN struct _EFI_FILE_HANDLE  *File) {

    if (File->FileObj == NULL) {
        printf("DummyClose() - closing a volume has no effect in the mock implementation\n");
        return EFI_SUCCESS;
    }

    fclose((FILE*)File->FileObj);
    (void)free(File);

    return EFI_SUCCESS;
}

static EFI_STATUS DummyRead (
    IN struct _EFI_FILE_HANDLE  *File,
    IN OUT UINTN                *BufferSize,
    OUT VOID                    *Buffer) {

    if (File->FileObj == NULL) {
        printf("DummyRead() - trying to read a volume is not supported.\n");
        return EFI_UNSUPPORTED;
    }

    *BufferSize = fread(Buffer, 1, *BufferSize, (FILE*)File->FileObj);

    return EFI_SUCCESS;
}

static EFI_STATUS DummyGetInfo(
    IN struct _EFI_FILE_HANDLE  *File,
    IN EFI_GUID                 *InformationType,
    IN OUT UINTN                *BufferSize,
    OUT VOID                    *Buffer
    ) {
 
    EFI_GUID FileInfoIdGuid = EFI_FILE_INFO_ID;

    if (strncmp((char*) InformationType, (char*) &FileInfoIdGuid, sizeof(EFI_GUID))) {
        printf("DummyGetInfo() - unsupported information type requested.\n");
        return EFI_UNSUPPORTED;
    }

    if (File->FileObj == NULL) {
        printf("DummyGetInfo() - unsupported on volume in mock implementation.\n");
        return EFI_UNSUPPORTED;
    }

    size_t pos = ftell((FILE*)File->FileObj);
    fseek((FILE*)File->FileObj, 0, SEEK_END);
    size_t FileSize = ftell((FILE*)File->FileObj);
    fseek((FILE*)File->FileObj, pos, SEEK_SET);

    ((EFI_FILE_INFO*) Buffer)->FileSize = FileSize;

    return EFI_SUCCESS;
}

static EFI_FILE DummyVolume = {
    .Open = DummyOpen,
    .Close = DummyClose,
    .Read = DummyRead,
    .GetInfo = DummyGetInfo,
    .FileObj = NULL
};


static EFI_STATUS DummyOpenVolume(IN struct _EFI_FILE_IO_INTERFACE *This,
    OUT struct _EFI_FILE_HANDLE         **Root) {

    *Root = &DummyVolume;

    return EFI_SUCCESS;
}

static EFI_FILE_IO_INTERFACE DummyFileIOInterface = {
    .OpenVolume = DummyOpenVolume
};


EFI_STATUS DummyHandleProtocol(void*, EFI_GUID*, void **Out) {
    printf("DummyHandleProtocol()\n");
    *Out = &DummyFileIOInterface;
    return EFI_SUCCESS;
}

extern EFI_BOOT_SERVICES *BS;

void mock_simplefs_init() {
    printf("mock_simplefs_init()\n");
    BS->HandleProtocol = DummyHandleProtocol;
    printf("BS->HandleProtocol: 0x%08X\n", BS->HandleProtocol);
}
