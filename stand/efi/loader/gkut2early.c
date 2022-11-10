#include "gkut2fs.h"
#include "gkut2dec.h"
#include "gkut2early.h"
#include "gkut2parse.h"
#include "gkut2auth.h"

void gkut2_free_read_necessary_result(gkut2_read_necessary_result *res) {
    (void)free(res->iv);
    (void)free(res->sym_pub);
    (void)free(res->sym_priv);
    (void)free(res->geli_key_enc);
    (void)free(res->policy_pcr);
}

EFI_STATUS gkut2_read_necessary(gkut2_read_necessary_result *res) {
    EFI_STATUS Status;
    UINT8 *iv_freeme = NULL;
    UINT64 iv_size = 1024;
    UINT8 *sym_pub_freeme = NULL;
    UINT64 sym_pub_size = 1024;
    UINT8 *sym_priv_freeme = NULL;
    UINT64 sym_priv_size = 1024;
    UINT8 *geli_key_enc_freeme = NULL;
    UINT64 geli_key_enc_size = 1024;
    UINT8 *policy_pcr_freeme = NULL;
    UINT64 policy_pcr_size = 1024;
    UINT8 *primary_handle_freeme = NULL;
    UINT64 primary_handle_size = 1024;
    UINT8 *primary_handle_zeroterm_freeme = NULL;

    Status = gkut2_efi_open_volume();
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_open_volume - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/iv", &iv_size, &iv_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_read_file - iv - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/sym.pub", &sym_pub_size, &sym_pub_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_read_file - sym.pub - %lu\n", Status);
        goto Error;
    }
    
    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/sym.priv", &sym_priv_size, &sym_priv_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_read_file - sym.priv - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/geli_key.enc", &geli_key_enc_size, &geli_key_enc_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_read_file - geli_key.enc - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/policy_pcr", &policy_pcr_size, &policy_pcr_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_read_file - policy_pcr - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/primary_handle", &primary_handle_size, &primary_handle_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_read_file - primary_handle - %lu\n", Status);
        goto Error;
    }
    primary_handle_zeroterm_freeme = strndup(primary_handle_freeme, primary_handle_size);

    Status = gkut2_efi_close_volume();
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_close_volume - %lu\n", Status);
        goto Error;
    }

    res->iv = iv_freeme;
    res->sym_pub = sym_pub_freeme;
    res->sym_priv = sym_priv_freeme;
    res->geli_key_enc = geli_key_enc_freeme;
    res->policy_pcr = policy_pcr_freeme;
    res->iv_size = iv_size;
    res->sym_pub_size = sym_pub_size;
    res->sym_priv_size = sym_priv_size;
    res->geli_key_enc_size = geli_key_enc_size;
    res->policy_pcr_size = policy_pcr_size;
    res->primary_handle = strtol(primary_handle_zeroterm_freeme, NULL, 0);

    (void)free(primary_handle_freeme);
    (void)free(primary_handle_zeroterm_freeme);

    return EFI_SUCCESS;

Error:
    (void)free(iv_freeme);
    (void)free(sym_pub_freeme);
    (void)free(sym_priv_freeme);
    (void)free(geli_key_enc_freeme);
    (void)free(policy_pcr_freeme);
    (void)free(primary_handle_freeme);
    (void)free(primary_handle_zeroterm_freeme);

    return Status;
}

EFI_STATUS gkut2_start_hmac_session(TPMI_SH_AUTH_SESSION *SessionHandle) {
	EFI_STATUS status;

	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;
	status = Tpm2StartAuthSession (
	    TPM_RH_NULL,	// TpmKey
	    TPM_RH_NULL,	// Bind
	    &NonceCaller,
	    &Salt,
	    TPM_SE_HMAC,	// SessionType
	    &Symmetric,
	    TPM_ALG_SHA256,	//AuthHash
	    SessionHandle,
	    &NonceTPM
	);
	if (status != EFI_SUCCESS) {
		printf("Tpm2StartAuthSession() failed - 0x%lx.\n", status);
		return status;
	}

	return EFI_SUCCESS;
}

EFI_STATUS gkut2_start_policy_session(TPMI_SH_AUTH_SESSION *SessionHandle, TPMS_PCR_SELECTION *pcr_selection) {
	EFI_STATUS status;

	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;
	status = Tpm2StartAuthSession (
	    TPM_RH_NULL,	// TpmKey
	    TPM_RH_NULL,	// Bind
	    &NonceCaller,
	    &Salt,
	    TPM_SE_POLICY,	// SessionType
	    &Symmetric,
	    TPM_ALG_SHA256,	//AuthHash
	    SessionHandle,
	    &NonceTPM
	);
	if (status != EFI_SUCCESS) {
		printf("Tpm2StartAuthSession() failed - 0x%lx.\n", status);
		return status;
	}

	TPM2B_DIGEST PcrDigest = { .size = 0 };
	TPML_PCR_SELECTION Pcrs = {
	    .count = 1,
	    .pcrSelections = {
	        *pcr_selection
	    }
	};
	status = Tpm2PolicyPCR(
	    *SessionHandle, 	// PolicySession
	    &PcrDigest,
	    &Pcrs
	);
	if (status != EFI_SUCCESS) {
		printf("Tpm2PolicyPCR() failed - 0x%lx.\n", status);
		return status;
	}

	return EFI_SUCCESS;
}

EFI_STATUS gkut2_decrypt_key(gkut2_read_necessary_result *input, UINT8 *key, UINT64 *key_size) {
    EFI_STATUS Status;
    TPMS_PCR_SELECTION pcr_selection;
    TPMI_SH_AUTH_SESSION HmacSessionHandle;
    TPMI_SH_AUTH_SESSION PcrSessionHandle;
    char *policy_pcr_freeme = strndup(input->policy_pcr, input->policy_pcr_size);

    if (policy_pcr_freeme == NULL) {
        printf("gkut2_decrypt_key - strndup - NULL\n");
        goto Error;
    }

    Status = gkut2_start_hmac_session(&HmacSessionHandle);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - gkut2_start_hmac_session - %lu\n", Status);
        goto Error;
    }

    TPMS_AUTH_COMMAND HmacAuthSession = {
        .sessionHandle = HmacSessionHandle,
        .nonce = { .size = 0 },
        .sessionAttributes = 0,
        .hmac = { .size = 0}
    };
    TPM_HANDLE SymKeyHandle;
    TPM2B_NAME SymKeyName;

    Status = Tpm2Load(input->primary_handle, &HmacAuthSession,
        input->sym_priv + 2, input->sym_priv_size - 2,
        input->sym_pub + 2, input->sym_pub_size - 2,
        &SymKeyHandle, &SymKeyName);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - Tpm2Load - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_parse_efivar_policy_spec(policy_pcr_freeme, &pcr_selection.hash,
        &pcr_selection.pcrSelect[0], &pcr_selection.sizeofSelect);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - gkut2_parse_efivar_policyspec - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_start_policy_session(&PcrSessionHandle, &pcr_selection);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - gkut2_start_policy_session - %lu\n", Status);
        goto Error;
    }

    TPMS_AUTH_COMMAND PcrAuthSession = {
        .sessionHandle = PcrSessionHandle,
        .nonce = { .size = 0 },
        .sessionAttributes = 0,
        .hmac = { .size = 0}
    };

    TPM2B_IV IvIn;
    IvIn.size = input->iv_size;
    memcpy(&IvIn.buffer[0], input->iv, input->iv_size);

    TPM2B_MAX_BUFFER InData;
    InData.size = input->geli_key_enc_size;
    memcpy(&InData.buffer[0], input->geli_key_enc, input->geli_key_enc_size);

    TPM2B_MAX_BUFFER OutData;
    TPM2B_IV OutIv;

    Status = Tpm2EncryptDecrypt(SymKeyHandle, &PcrAuthSession,
        1 /* decrypt */, TPM_ALG_NULL /* mode */,
        &IvIn, &InData, &OutData, &OutIv);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - Tpm2EncryptDecrypt - %lu\n", Status);
        goto Error;
    }

    if (OutData.size > *key_size) {
        printf("gkut2_decrypt_key - decrypted key size too large - %d\n", OutData.size);
        goto Error;
    }

    memcpy(key, &OutData.buffer[0], OutData.size);
    *key_size = OutData.size;

    return EFI_SUCCESS;

Error:
    (void)free(policy_pcr_freeme);

    return Status;
}
