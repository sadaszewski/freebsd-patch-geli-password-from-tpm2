#ifndef _DUMMY_EFI_H_
#define _DUMMY_EFI_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

typedef unsigned char BOOLEAN;
typedef char INT8;
typedef unsigned char CHAR8;
typedef short INT16;
typedef unsigned short CHAR16;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long long UINT64;
typedef UINT64 UINTN;
typedef UINT64 EFI_PHYSICAL_ADDRESS;

typedef UINT32 EFI_STATUS;

typedef void VOID;

typedef struct {
    UINT32 a;
    UINT16 b;
    UINT16 c;
    UINT8 d[8];
} EFI_GUID;

typedef struct {
    void (*Exit)(void*, int, int, void*);
    EFI_STATUS (*LocateProtocol)(EFI_GUID*, void*, void**);
    EFI_STATUS (*HandleProtocol)(void*, EFI_GUID*, void**);
} EFI_BOOT_SERVICES;


typedef struct {
} EFI_CONFIGURATION_TABLE;

extern EFI_BOOT_SERVICES *BS;

extern void *IH;

#define EFI_SUCCESS 0
#define EFI_INVALID_PARAMETER 1
#define EFI_DEVICE_ERROR 2
#define EFI_NOT_FOUND 3
#define EFI_UNSUPPORTED 4
#define EFI_BAD_BUFFER_SIZE 5
#define EFI_BUFFER_TOO_SMALL 6
#define EFI_NOT_READY 7

//#define EFI_TCG2_SUBMIT_COMMAND 3
//#define EFI_TCG2_GET_ACTIVE_PCR_BANKS 4
//typedef (*EFI_TCG2_GET_CAPABILITY)();
//typedef (*EFI_TCG2_GET_EVENT_LOG)();

#define EFI_ERROR(s) ((s) != EFI_SUCCESS)

#define IN
#define OUT
#define INOUT

#define EFIAPI

void efi_exit(EFI_STATUS);

#endif

