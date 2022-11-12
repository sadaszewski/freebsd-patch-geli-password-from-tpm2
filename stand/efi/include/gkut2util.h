#ifndef _GKUT2_UTIL_H_
#define _GKUT2_UTIL_H_

#include <efi.h>

EFI_STATUS gkut2_bin2hex(UINT8 *bin, UINT64 bin_len, UINT8 *hex);

EFI_STATUS gkut2_hex2bin(UINT8 *hex, UINT8 *bin, UINT64 *bin_len);

EFI_STATUS gkut2_random_bytes(UINT8 *output, UINTN length);

#endif
