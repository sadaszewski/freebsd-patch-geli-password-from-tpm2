#include "gkut2fs.h"
#include "gkut2dec.h"
#include "gkut2early.h"
#include "gkut2parse.h"
#include "gkut2auth.h"
#include "gkut2util.h"

#include <stdio.h>

EFI_STATUS gkut2_read_necessary(GKUT2_READ_NECESSARY_RESULT *res) {
    EFI_STATUS Status;
    UINT64 Size;

    if (res == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    Status = gkut2_efi_open_volume();
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_open_volume - %lu\n", Status);
        return Status;
    }

    Size = sizeof(res->salt.buffer);
    Status = gkut2_efi_read_file("/efi/freebsd/gkut2/salt", &Size, &res->salt.buffer[0], 0);
    res->salt.size = Size;
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_read_file - salt - %lu\n", Status);
        return Status;
    }

    Size = sizeof(res->iv.buffer);
    Status = gkut2_efi_read_file("/efi/freebsd/gkut2/iv", &Size, &res->iv.buffer[0], 0);
    res->iv.size = Size;
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_read_file - iv - %lu\n", Status);
        return Status;
    }

    Size = sizeof(res->sym_pub.buffer);
    Status = gkut2_efi_read_file("/efi/freebsd/gkut2/sym.pub", &Size, (UINT8*) &res->sym_pub.buffer[0], 2);
    res->sym_pub.size = Size;
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_read_file - sym.pub - %lu\n", Status);
        return Status;
    }
    
    Size = sizeof(res->sym_priv.buffer);
    Status = gkut2_efi_read_file("/efi/freebsd/gkut2/sym.priv", &Size, &res->sym_priv.buffer[0], 2);
    res->sym_priv.size = Size;
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_read_file - sym.priv - %lu\n", Status);
        return Status;
    }

    Size = sizeof(res->geli_key_enc.buffer);
    Status = gkut2_efi_read_file("/efi/freebsd/gkut2/geli_key.enc", &Size, &res->geli_key_enc.buffer[0], 0);
    res->geli_key_enc.size = Size;
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_read_file - geli_key.enc - %lu\n", Status);
        return Status;
    }

    Size = sizeof(res->policy_pcr.buffer) - 1;
    Status = gkut2_efi_read_file("/efi/freebsd/gkut2/policy_pcr", &Size, &res->policy_pcr.buffer[0], 0);
    res->policy_pcr.size = Size;
    res->policy_pcr.buffer[Size] = 0;
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_read_file - policy_pcr - %lu\n", Status);
        return Status;
    }

    GKUT2B_HANDLE_TEXT primary_handle_text;
    Size = sizeof(primary_handle_text.buffer) - 1;
    Status = gkut2_efi_read_file("/efi/freebsd/gkut2/primary_handle", &Size, &primary_handle_text.buffer[0], 0);
    primary_handle_text.size = Size;
    primary_handle_text.buffer[Size] = 0;
    res->primary_handle = strtol(&primary_handle_text.buffer[0], NULL, 0);
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_efi_read_file - primary_handle - %lu\n", Status);
        return Status;
    }

    Status = gkut2_efi_close_volume();
    if (EFI_ERROR(Status)) {
        printf("gkut2_read_necessary - gkut2_close_volume - %lu\n", Status);
        return Status;
    }

    return EFI_SUCCESS;
}

EFI_STATUS gkut2_start_hmac_session(TPMI_SH_AUTH_SESSION *SessionHandle) {
	EFI_STATUS status;

	TPM2B_DIGEST NonceCaller = { .size = 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { .size = 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;

    status = gkut2_random_bytes(&NonceCaller.buffer[0], NonceCaller.size);
    if (EFI_ERROR(status)) {
        printf("gkut2_start_hmac_session - gkut2_random_bytes - 0x%lX\n", status);
        return status;
    }

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

	TPM2B_DIGEST NonceCaller = { .size = 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { .size = 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;

    status = gkut2_random_bytes(&NonceCaller.buffer[0], NonceCaller.size);
    if (EFI_ERROR(status)) {
        printf("gkut2_start_policy_session - gkut2_random_bytes - 0x%lX\n", status);
        return status;
    }

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

EFI_STATUS gkut2_decrypt_key(GKUT2_READ_NECESSARY_RESULT *input, UINT8 *key, UINT64 *key_size) {
    EFI_STATUS Status;
    TPMS_PCR_SELECTION pcr_selection;
    TPMI_SH_AUTH_SESSION HmacSessionHandle;
    TPMI_SH_AUTH_SESSION PcrSessionHandle;

    Status = gkut2_start_hmac_session(&HmacSessionHandle);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - gkut2_start_hmac_session - %lu\n", Status);
        return Status;
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
        &input->sym_priv.buffer[0], input->sym_priv.size,
        &input->sym_pub.buffer[0], input->sym_pub.size,
        &SymKeyHandle, &SymKeyName);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - Tpm2Load - %lu\n", Status);
        return Status;
    }

    Status = gkut2_parse_efivar_policy_spec(&input->policy_pcr.buffer[0], &pcr_selection.hash,
        &pcr_selection.pcrSelect[0], &pcr_selection.sizeofSelect);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - gkut2_parse_efivar_policyspec - %lu\n", Status);
        return Status;
    }

    Status = gkut2_start_policy_session(&PcrSessionHandle, &pcr_selection);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - gkut2_start_policy_session - %lu\n", Status);
        return Status;
    }

    TPMS_AUTH_COMMAND PcrAuthSession = {
        .sessionHandle = PcrSessionHandle,
        .nonce = { .size = 0 },
        .sessionAttributes = 0,
        .hmac = { .size = 0}
    };

    TPM2B_MAX_BUFFER InData;
    InData.size = input->geli_key_enc.size;
    memcpy(&InData.buffer[0], &input->geli_key_enc.buffer[0], input->geli_key_enc.size);

    TPM2B_MAX_BUFFER OutData;
    TPM2B_IV OutIv;

    Status = Tpm2EncryptDecrypt(SymKeyHandle, &PcrAuthSession,
        1 /* decrypt */, TPM_ALG_NULL /* mode */,
        &input->iv, &InData, &OutData, &OutIv);
    if (EFI_ERROR(Status)) {
        printf("gkut2_decrypt_key - Tpm2EncryptDecrypt - %lu\n", Status);
        explicit_bzero(&OutData.buffer[0], sizeof(OutData.buffer));
        return Status;
    }

    if (OutData.size > *key_size) {
        printf("gkut2_decrypt_key - decrypted key size too large - %d\n", OutData.size);
        explicit_bzero(&OutData.buffer[0], sizeof(OutData.buffer));
        return EFI_BUFFER_TOO_SMALL;
    }

    memcpy(key, &OutData.buffer[0], OutData.size);
    *key_size = OutData.size;
    explicit_bzero(&OutData.buffer[0], sizeof(OutData.buffer));

    return EFI_SUCCESS;
}
