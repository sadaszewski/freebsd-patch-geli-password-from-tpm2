#ifndef _GKUT2_EARLY_H_
#define _GKUT2_EARLY_H_

#include <efi.h>

#include <IndustryStandard/Tpm20.h>

#define GKUT2_GELI_KEY_MAX_SIZE 64
#define GKUT2_SALT_MAX_SIZE 64
#define GKUT2_POLICY_PCR_TEXT_MAX_SIZE 255
#define GKUT2_HANDLE_TEXT_MAX_SIZE 16

typedef struct {
    UINT8 size;
    UINT8 buffer[GKUT2_GELI_KEY_MAX_SIZE];
} GKUT2B_GELI_KEY;

typedef struct {
    UINT8 size;
    UINT8 buffer[GKUT2_SALT_MAX_SIZE];
} GKUT2B_SALT;

typedef struct {
    UINT8 size;
    UINT8 buffer[GKUT2_POLICY_PCR_TEXT_MAX_SIZE];
} GKUT2B_POLICY_PCR_TEXT;

typedef struct {
    UINT8 size;
    UINT8 buffer[GKUT2_HANDLE_TEXT_MAX_SIZE];
} GKUT2B_HANDLE_TEXT;

typedef struct {
    UINT16 size;
    UINT8 buffer[sizeof(TPMT_PUBLIC)];
} GKUT2B_PUBLIC;

typedef struct {
    GKUT2B_SALT salt;
    TPM2B_IV iv;
    GKUT2B_PUBLIC sym_pub;
    TPM2B_PRIVATE sym_priv;
    GKUT2B_GELI_KEY geli_key_enc;
    GKUT2B_POLICY_PCR_TEXT policy_pcr;
    UINT32 primary_handle;
} GKUT2_READ_NECESSARY_RESULT;

EFI_STATUS gkut2_read_necessary(GKUT2_READ_NECESSARY_RESULT *res);

EFI_STATUS gkut2_start_hmac_session(TPMI_SH_AUTH_SESSION *SessionHandle);

EFI_STATUS gkut2_start_policy_session(TPMI_SH_AUTH_SESSION *SessionHandle, TPMS_PCR_SELECTION *pcr_selection);

EFI_STATUS gkut2_decrypt_key(GKUT2_READ_NECESSARY_RESULT *input, UINT8 *key, UINT64 *key_size);

#endif
