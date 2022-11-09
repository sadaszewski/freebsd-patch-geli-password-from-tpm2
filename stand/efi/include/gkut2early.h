#ifndef _GKUT2_EARLY_H_
#define _GKUT2_EARLY_H_

#include <efi.h>

typedef struct {
    UINT8 *iv, *sym_pub, *sym_priv, *passphrase_enc, *policy_pcr;
    UINT64 iv_size, sym_pub_size, sym_priv_size, passphrase_enc_size, policy_pcr_size;
} gkut2_read_necessary_result;

EFI_STATUS gkut2_read_necessary(gkut2_read_necessary_result *res);

void gkut2_free_read_necessary_result(gkut2_read_necessary_result *res);

#endif

