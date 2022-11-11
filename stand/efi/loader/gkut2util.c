#include <efi.h>

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
        UINT32 val;
        if (sscanf(hex, "%02x", &val) != 1) {
            return EFI_BUFFER_TOO_SMALL;
        }
        *bin = val;
        bin++;
        hex += 2;
        *bin_len += 1;
    }

    return EFI_SUCCESS;
}
