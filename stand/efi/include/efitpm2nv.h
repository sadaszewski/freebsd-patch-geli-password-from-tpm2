#ifndef _EFITPM2NV_H_
#define _EFITPM2NV_H_

#include <efi.h>
#include <IndustryStandard/Tpm20.h>

EFI_STATUS Tpm2NvReadPublic (
	TPMI_RH_NV_INDEX NvIndex,
	TPM2B_NV_PUBLIC *NvPublic,
	TPM2B_NAME *NvName);
	
EFI_STATUS Tpm2NvRead (
	TPMI_RH_NV_AUTH AuthHandle,
	TPMI_RH_NV_INDEX NvIndex,
	TPMS_AUTH_COMMAND *AuthSession,
	UINT16 Size,
	UINT16 Offset,
	TPM2B_MAX_BUFFER *OutData
);

EFI_STATUS Tpm2StartAuthSession (
	TPMI_DH_OBJECT			TpmKey,
	TPMI_DH_ENTITY			Bind,
	TPM2B_NONCE			*NonceCaller,
	TPM2B_ENCRYPTED_SECRET	*Salt,
	TPM_SE					SessionType,
	TPMT_SYM_DEF			*Symmetric,
	TPMI_ALG_HASH			AuthHash,
	TPMI_SH_AUTH_SESSION	*SessionHandle,
	TPM2B_NONCE			*NonceTPM
);

EFI_STATUS Tpm2PolicyPCR(
	TPMI_SH_POLICY		PolicySession,
	TPM2B_DIGEST		*PcrDigest,
	TPML_PCR_SELECTION	*Pcrs
);

EFI_STATUS Tpm2NvReadLock (
    TPMI_RH_NV_AUTH		AuthHandle,
    TPMI_RH_NV_INDEX	NvIndex,
    TPMS_AUTH_COMMAND	*AuthSession
);

EFI_STATUS Tpm2PcrExtend (
    TPMI_DH_PCR         PcrHandle,
    TPML_DIGEST_VALUES  *Digests
);

EFI_STATUS Tpm2LocateProtocol();

#endif

