#ifndef _GKUT2_DEC_H_
#define _GKUT2_DEC_H_

#include <IndustryStandard/Tpm20.h>

EFI_STATUS Tpm2EncryptDecrypt(
    TPMI_DH_OBJECT        KeyHandle,
    TPMS_AUTH_COMMAND     *AuthSession,
    TPMI_YES_NO           Decrypt,
    TPMI_ALG_SYM_MODE     Mode,
    TPM2B_IV              *IvIn,
    TPM2B_MAX_BUFFER      *InData,
    TPM2B_MAX_BUFFER      *OutData,
    TPM2B_IV              *OutIv);

EFI_STATUS Tpm2ContextSave(TPMI_DH_CONTEXT SaveHandle, TPMS_CONTEXT *Context);

EFI_STATUS Tpm2ContextLoad(UINT64 Sequence, TPMI_DH_CONTEXT SavedHandle, TPMI_RH_HIERARCHY Hierarchy,
    TPM2B_CONTEXT_DATA *ContextBlob, TPMI_DH_CONTEXT *LoadedHandle);

EFI_STATUS Tpm2CreatePrimary_Preamble(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession,
    TPM2B_SENSITIVE_CREATE *InSensitive, UINT8 **BufferInOut);


EFI_STATUS Tpm2CreatePrimary(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    TPM2B_SENSITIVE_CREATE *InSensitive, // in
    TPM2B_PUBLIC *InPublic, TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_PUBLIC *OutPublic, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name); // out

void Uint32ToObjectAttributes(UINT32 AttrIn, TPMA_OBJECT *AttrOut);

EFI_STATUS DecodePublicParamsAndId_Aes(UINT8 **BufferInOut, TPM2B_PUBLIC *OutPublic);

EFI_STATUS DecodePublicParamsAndId_Nop(UINT8 **BufferInOut, TPM2B_PUBLIC *OutPublic);

EFI_STATUS Tpm2CreatePrimary_Epilogue(TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION *PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_PUBLIC *OutPublic, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name, // out
    UINT8 *BufferStart, UINT8* BufferCur, // state
    EFI_STATUS(*DecodePublicParamsAndId_Callback)(UINT8**, TPM2B_PUBLIC*)); // callback

UINT32 ObjectAttributesToUint32(TPMA_OBJECT *ObjectAttributes);

EFI_STATUS Tpm2CreatePrimaryAes(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    TPM2B_SENSITIVE_CREATE *InSensitive, // in
    TPMI_ALG_HASH NameAlg, TPMA_OBJECT *ObjectAttributes, TPM2B_DIGEST *AuthPolicy, // in
    TPMI_AES_KEY_BITS KeyBits, TPMI_ALG_SYM_MODE SymMode, // in 
    TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION *PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_PUBLIC *OutPublic, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name); // out

EFI_STATUS Tpm2CreatePrimary_PremarshalledPublic(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    TPM2B_SENSITIVE_CREATE *InSensitive, // in
    UINT8 *InPublicPremarshalled, UINT16 InPublicPremarshalledSize, // in 
    TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION *PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name); // out

EFI_STATUS Tpm2Load(TPMI_DH_OBJECT ParentHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    UINT8 *InPrivateMarshalled, UINT16 InPrivateMarshalledSize, // in
    UINT8 *InPublicMarshalled, UINT16 InPublicMarshalledSize, // in
    TPM_HANDLE *ObjectHandle, TPM2B_NAME *Name); // out

#endif // _GKUT2_DEC_H_
