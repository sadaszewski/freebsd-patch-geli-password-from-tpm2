#include <efi.h>

static UINT8 encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

static UINT32 mod_table[] = {0, 2, 1};

EFI_STATUS gkut2_base64_encode(const UINT8 *data,
    UINT64 input_length,
    UINT8 *encoded_data,
    UINT64 *output_length) {

    if (data == NULL || encoded_data == NULL || output_length == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    *output_length = 4 * ((input_length + 2) / 3);

    for (UINT64 i = 0, j = 0; i < input_length;) {

        UINT32 octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        UINT32 octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        UINT32 octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        UINT32 triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (UINT32 i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return EFI_SUCCESS;
}
