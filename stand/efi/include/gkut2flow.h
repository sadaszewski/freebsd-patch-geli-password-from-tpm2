#ifndef _GKUT2FLOW_H_
#define _GKUT2FLOW_H_

#include <efi.h>

typedef struct {
    UINT8 KeyWasDecrypted;
} GKUT2_STATE;

EFI_STATUS gkut2_early(GKUT2_STATE *state);

void gkut2_late(GKUT2_STATE *state);

void gkut2_destroy_crypto_info();

#endif
