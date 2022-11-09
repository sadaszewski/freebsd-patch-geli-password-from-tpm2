#ifndef _GKUT2_EARLY_H_
#define _GKUT2_EARLY_H_

#include <efi.h>

typedef struct {
    UINT8 *iv, *sym_pub, *sym_priv, *passphrase_enc, *policy_pcr;
    UINT64 iv_size, sym_pub_size, sym_priv_size, passphrase_enc_size, policy_pcr_size;
} gkut2_early_result;

EFI_STATUS gkut2_early(gkut2_early_result *res);

void gkut2_free_early_result(gkut2_early_result *res);

#endif

