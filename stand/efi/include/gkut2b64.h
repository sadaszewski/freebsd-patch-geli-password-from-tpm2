#ifndef _GKUT2B64_H_
#define _GKUT2B64_H_

EFI_STATUS gkut2_base64_encode(const UINT8 *data,
    UINT64 input_length,
    UINT8 *encoded_data,
    UINT64 *output_length);

#endif
