#ifndef _GKUT2_EARLY_H_
#define _GKUT2_EARLY_H_

#include <efi.h>

#include <IndustryStandard/Tpm20.h>

typedef struct {
    UINT8 *iv, *sym_pub, *sym_priv, *geli_key_enc, *policy_pcr;
    UINT64 iv_size, sym_pub_size, sym_priv_size, geli_key_enc_size, policy_pcr_size;
    UINT32 primary_handle;
} gkut2_read_necessary_result;

EFI_STATUS gkut2_read_necessary(gkut2_read_necessary_result *res);

void gkut2_free_read_necessary_result(gkut2_read_necessary_result *res);

EFI_STATUS gkut2_start_policy_session(TPMI_SH_AUTH_SESSION *SessionHandle, TPMS_PCR_SELECTION *pcr_selection);

EFI_STATUS gkut2_decrypt_key(gkut2_read_necessary_result *input, UINT8 *key, UINT64 *key_size);

#endif
