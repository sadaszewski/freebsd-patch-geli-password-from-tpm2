#include <efi.h>
#include <efirng.h>

#include <stdio.h>

EFI_STATUS gkut2_bin2hex(UINT8 *bin, UINT64 bin_len, UINT8 *hex) {
    if (bin == NULL || hex == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    for (UINT64 i = 0; i < bin_len; i++) {
		snprintf(hex + i * 2, 3, "%02x", bin[i]);
	}
	hex[2 * bin_len] = '\0';

    return EFI_SUCCESS;
}

EFI_STATUS gkut2_hex2bin(UINT8 *hex, UINT8 *bin, UINT64 *bin_len) {
    if (hex == NULL || bin == NULL || bin_len == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    *bin_len = 0;
    while (*hex) {
        UINT32 val = 0;
        for (int i = 0; i < 2; i++) {
            UINT8 ch = hex[i];
            if (ch == 0) {
                return EFI_BUFFER_TOO_SMALL;
            }
            if (ch >= 'a' && ch <= 'f') {
                ch = 10 + (ch - 'a');
            } else if (ch >= 'A' && ch <= 'F') {
                ch = 10 + (ch - 'A');
            } else if (ch >= '0' && ch <= '9') {
                ch = ch - '0';
            } else {
                return EFI_INVALID_PARAMETER;
            }
            val <<= 4;
            val |= ch;
        }
        *bin = val;
        bin++;
        hex += 2;
        *bin_len += 1;
    }

    return EFI_SUCCESS;
}


EFI_STATUS gkut2_random_bytes(UINT8 *output, UINTN length) {
    EFI_GUID guid = EFI_RNG_PROTOCOL_GUID;
    EFI_RNG_PROTOCOL *protocol;
    EFI_STATUS status;

    status = BS->LocateProtocol(&guid, NULL, (void**) &protocol);
    if (EFI_ERROR(status)) {
        printf("gkut2_random_bytes - LocateProtocol - 0x%lX\n", status);
        return status;
    }

    status = protocol->GetRNG(protocol, NULL, length, output);
    if (EFI_ERROR(status)) {
        printf("gkut2_random_bytes - GetRNG - 0x%lX\n", status);
        return status;
    }

    return EFI_SUCCESS;
}
