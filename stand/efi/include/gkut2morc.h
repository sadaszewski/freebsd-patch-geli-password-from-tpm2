#ifndef _GKUT2MORC_H_
#define _GKUT2MORC_H_

#include <efi.h>

#define MEMORY_OVERWRITE_REQUEST_CONTROL_GUID \
    {  0xe20939be,  0x32d4,  0x41be,  0xa1,  0x50,  0x89,  0x7f,  0x85, 0xd4, \
        0x98, 0x29 }

#define MEMORY_OVERWRITE_REQUEST_CONTROL_LOCK_GUID \
    {  0xBB983CCF,  0x151D,  0x40E1,  0xA0,  0x7B,  0x4A,  0x17,  0xBE, 0x16, \
        0x82, 0x92 }

#define MEMORY_OVERWRITE_REQUEST_CONTROL_VARNAME "MemoryOverwriteRequestControl"

#define MEMORY_OVERWRITE_REQUEST_CONTROL_LOCK_VARNAME "MemoryOverwriteRequestControlLock"

EFI_STATUS gkut2_request_memory_overwrite();

#endif
