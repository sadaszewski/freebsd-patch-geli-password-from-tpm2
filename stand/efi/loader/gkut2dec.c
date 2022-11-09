/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2021 Stanislaw R. Adaszewski
 * All rights reserved.
 *
 *	@(#)gkut2dec.c	13.1 (Villeneuve) 11/02/22
 */


#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>

#include "gkut2tcg.h"

#pragma pack(1)

typedef struct {
    TPM2_COMMAND_HEADER   Header;
    TPMI_DH_OBJECT        KeyHandle;
    UINT32                AuthSessionSize;
    TPMS_AUTH_COMMAND     AuthSession;
    TPMI_YES_NO           Decrypt;
    TPMI_ALG_SYM_MODE     Mode;
    TPM2B_IV              IvIn;
    TPM2B_MAX_BUFFER      InData;
} TPM2_ENCRYPT_DECRYPT_COMMAND;

typedef struct {
    TPM2_RESPONSE_HEADER  Header;
    UINT32                AuthSessionSize;
    TPM2B_MAX_BUFFER      OutData;
    TPM2B_IV              IvOut;
    TPMS_AUTH_RESPONSE    AuthSession;
} TPM2_ENCRYPT_DECRYPT_RESPONSE;

typedef struct {
    TPM2_COMMAND_HEADER Header;
    TPMI_DH_CONTEXT SaveHandle;
} TPM2_CONTEXT_SAVE_COMMAND;

typedef struct {
    TPM2_RESPONSE_HEADER Header;
    TPMS_CONTEXT Context;
} TPM2_CONTEXT_SAVE_RESPONSE;

typedef struct {
    TPM2_COMMAND_HEADER   Header;
    TPMS_CONTEXT          Context;
} TPM2_CONTEXT_LOAD_COMMAND;

typedef struct {
    TPM2_RESPONSE_HEADER  Header;
    TPMI_DH_CONTEXT       LoadedHandle;
} TPM2_CONTEXT_LOAD_RESPONSE;

typedef struct {
    TPM2_COMMAND_HEADER     Header;
    TPMI_RH_HIERARCHY       PrimaryHandle;
    UINT32                  AuthSessionSize;
    TPMS_AUTH_COMMAND       AuthSession;
    TPM2B_SENSITIVE_CREATE  InSensitive;
    TPM2B_PUBLIC            InPublic;
    TPM2B_DATA              OutsideInfo;
    TPML_PCR_SELECTION      PcrSelection;
} TPM2_CREATE_PRIMARY_COMMAND;

typedef struct {
    TPM2_RESPONSE_HEADER    Header;
    TPM_HANDLE              ObjectHandle;
    UINT32                  AuthSessionSize;
    TPM2B_PUBLIC            OutPublic;
    TPM2B_CREATION_DATA     CreationData;
    TPM2B_DIGEST            CreationHash;
    TPMT_TK_CREATION        CreationTicket;
    TPM2B_NAME              Name;
    TPMS_AUTH_RESPONSE      AuthSession;
} TPM2_CREATE_PRIMARY_RESPONSE;

typedef struct {
    TPM2_COMMAND_HEADER     Header;
    TPMI_DH_OBJECT          ParentHandle;
    TPM2B_PRIVATE           InPrivate;
    TPM2B_PUBLIC            InPublic;
} TPM2_LOAD_COMMAND;

typedef struct {
    TPM2_RESPONSE_HEADER    Header;
    TPM_HANDLE              ObjectHandle;
    TPM2B_NAME              Name;
} TPM2_LOAD_RESPONSE;

#pragma pack()


EFI_STATUS Tpm2EncryptDecrypt(
    TPMI_DH_OBJECT        KeyHandle,
    TPMS_AUTH_COMMAND     *AuthSession,
    TPMI_YES_NO           Decrypt,
    TPMI_ALG_SYM_MODE     Mode,
    TPM2B_IV              *IvIn,
    TPM2B_MAX_BUFFER      *InData,
    TPM2B_MAX_BUFFER      *OutData,
    TPM2B_IV              *OutIv) {

    EFI_STATUS Status;
    TPM2_ENCRYPT_DECRYPT_COMMAND    SendBuffer;
    TPM2_ENCRYPT_DECRYPT_RESPONSE   RecvBuffer;
    UINT32 SendBufferSize;
    UINT32 RecvBufferSize;
    UINT8 *Buffer;
    TPM_RC ResponseCode;
    UINT32 SessionInfoSize;

    SendBuffer.Header.tag = SwapBytes16(TPM_ST_SESSIONS);
    SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_EncryptDecrypt);

    SendBuffer.KeyHandle = SwapBytes32(KeyHandle); 

    Buffer = (UINT8*) &SendBuffer.AuthSession;
    SessionInfoSize = CopyAuthSessionCommand(AuthSession, Buffer);
    Buffer += SessionInfoSize;
    SendBuffer.AuthSessionSize = SwapBytes32(SessionInfoSize);

    *Buffer = Decrypt;
    Buffer++;

    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(Mode));
    Buffer += sizeof(UINT16);

    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(IvIn->size));
    Buffer += sizeof(UINT16);

    memcpy(Buffer, &IvIn->buffer[0], IvIn->size);
    Buffer += IvIn->size;

    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InData->size));
    Buffer += sizeof(UINT16);

    memcpy(Buffer, &InData->buffer[0], InData->size);
    Buffer += InData->size;

	SendBufferSize = (UINT32)(Buffer - (UINT8 *)&SendBuffer);
	SendBuffer.Header.paramSize = SwapBytes32 (SendBufferSize);
 
	RecvBufferSize = sizeof (RecvBuffer);
	Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR (Status)) {
		goto Done;
	}	

	if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2EncryptDecrypt - RecvBufferSize Error - %x\n", RecvBufferSize);
		Status = EFI_DEVICE_ERROR;
		goto Done;
	}
	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		printf("Tpm2EncryptDecrypt - responseCode - %x\n", ResponseCode);
        Status = EFI_DEVICE_ERROR;
        goto Done;
	}

    /* printf("RecvBufferSize: %d\n", RecvBufferSize);
    for (int i = 0; i < RecvBufferSize; i++) {
        printf("%02X ", ((UINT8*) &RecvBuffer)[i]);
    }
    printf("\n"); */

    Buffer = (UINT8*) &RecvBuffer.AuthSessionSize;
    UINT32 sz = SwapBytes32(ReadUnaligned32((UINT32*) Buffer));
    Buffer += sizeof(UINT32);
    // printf("AuthSessionSize: %d\n", sz);

    OutData->size = SwapBytes16(ReadUnaligned16((UINT16*) Buffer));
    Buffer += sizeof(UINT16);
    if (OutData->size > MAX_DIGEST_BUFFER) {
		printf("Tpm2EncryptDecrypt - OutData->size error %x\n", OutData->size);
		Status = EFI_DEVICE_ERROR;
		goto Done;
    }
    memcpy(&OutData->buffer[0], Buffer, OutData->size);
    // printf("OutData->size: %d\n", OutData->size);
    Buffer += OutData->size;

    OutIv->size = SwapBytes16(ReadUnaligned16((UINT16*) Buffer));
    Buffer += sizeof(UINT16);
    // printf("OutIv->size: %d\n", OutIv->size);
    if (OutIv->size > MAX_SYM_BLOCK_SIZE) {
		printf("Tpm2EncryptDecrypt - OutIv->size error %x\n", OutIv->size);
		Status = EFI_DEVICE_ERROR;
		goto Done;
    }
    memcpy(&OutIv->buffer[0], Buffer, OutIv->size);
    Buffer += OutIv->size;

Done:
	bzero (&SendBuffer, sizeof(SendBuffer));
	bzero (&RecvBuffer, sizeof(RecvBuffer));
  
	return Status;
}


EFI_STATUS Tpm2ContextSave(TPMI_DH_CONTEXT SaveHandle, TPMS_CONTEXT *Context) {
    EFI_STATUS Status;
    TPM2_CONTEXT_SAVE_COMMAND SendBuffer;
    TPM2_CONTEXT_SAVE_RESPONSE RecvBuffer;
    UINT8 *Buffer;
    UINT32 SendBufferSize;
    UINT32 RecvBufferSize;
    TPM_RC ResponseCode;

    SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
    SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_ContextSave);

    SendBuffer.SaveHandle = SwapBytes32(SaveHandle);

    SendBufferSize = sizeof(SendBuffer);
    SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
	
    RecvBufferSize = sizeof (RecvBuffer);
	Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR (Status)) {
		return Status;
	}

	if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2ContextSave - RecvBufferSize Error - %x\n", RecvBufferSize);
		return EFI_DEVICE_ERROR;
	}
	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		printf("Tpm2ContextSave - responseCode - %x\n", ResponseCode);
        return EFI_DEVICE_ERROR;
	}

    Context->sequence = SwapBytes64(RecvBuffer.Context.sequence);
    Context->savedHandle = SwapBytes32(RecvBuffer.Context.savedHandle);
    Context->hierarchy = SwapBytes32(RecvBuffer.Context.hierarchy);
    Context->contextBlob.size = SwapBytes16(RecvBuffer.Context.contextBlob.size);
    memcpy(&Context->contextBlob.buffer[0],
        &RecvBuffer.Context.contextBlob.buffer[0], 
        Context->contextBlob.size);

    return EFI_SUCCESS;
}


EFI_STATUS Tpm2ContextLoad(UINT64 Sequence, TPMI_DH_CONTEXT SavedHandle, TPMI_RH_HIERARCHY Hierarchy,
    TPM2B_CONTEXT_DATA *ContextBlob, TPMI_DH_CONTEXT *LoadedHandle) {

    EFI_STATUS Status;
    TPM2_CONTEXT_LOAD_COMMAND SendBuffer;
    TPM2_CONTEXT_LOAD_RESPONSE RecvBuffer;
    UINT8 *Buffer;
    UINT32 SendBufferSize;
    UINT32 RecvBufferSize;
    TPM_RC ResponseCode;

    SendBuffer.Header.tag = SwapBytes16(TPM_ST_NO_SESSIONS);
    SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_ContextLoad);

    SendBuffer.Context.sequence = SwapBytes64(Sequence);
    SendBuffer.Context.savedHandle = SwapBytes32(SavedHandle);
    SendBuffer.Context.hierarchy = SwapBytes32(Hierarchy);
    SendBuffer.Context.contextBlob.size = SwapBytes16(ContextBlob->size);
    Buffer = (UINT8*) &SendBuffer.Context.contextBlob.buffer[0];
    memcpy(Buffer, &ContextBlob->buffer[0], ContextBlob->size);
    Buffer += ContextBlob->size;

    SendBufferSize = (UINT32)(Buffer - (UINT8*) &SendBuffer);
    SendBuffer.Header.paramSize = SwapBytes32(SendBufferSize);
    printf("SendBufferSize: %d\n", SendBufferSize);
    printf("ContextBlob->size: %d\n", ContextBlob->size);
	
    RecvBufferSize = sizeof (RecvBuffer);
	Status = Tpm2SubmitCommand (SendBufferSize, (UINT8 *)&SendBuffer, &RecvBufferSize, (UINT8 *)&RecvBuffer);
	if (EFI_ERROR (Status)) {
		return Status;
	}

	if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2ContextLoad - RecvBufferSize Error - %x\n", RecvBufferSize);
		return EFI_DEVICE_ERROR;
	}
	ResponseCode = SwapBytes32(RecvBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		printf("Tpm2ContextLoad - responseCode - %x\n", ResponseCode);
        return EFI_DEVICE_ERROR;
	}

    *LoadedHandle = SwapBytes32(RecvBuffer.LoadedHandle);

    return EFI_SUCCESS;
}


EFI_STATUS Tpm2CreatePrimary_Preamble(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession,
    TPM2B_SENSITIVE_CREATE *InSensitive, UINT8 **BufferInOut) {

    UINT8 *Buffer = *BufferInOut;

    UINT32 SessionInfoSize;
    
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(TPM_ST_SESSIONS));
    Buffer += sizeof(UINT16);
    Buffer += sizeof(UINT32); // skip paramSize for now
    WriteUnaligned32((UINT32*) Buffer, SwapBytes32(TPM_CC_CreatePrimary));
    Buffer += sizeof(UINT32);

    WriteUnaligned32((UINT32*) Buffer, SwapBytes32(PrimaryHandle));
    Buffer += sizeof(UINT32);

    UINT8 *AuthSessionSize = Buffer;
    Buffer += sizeof(UINT32);
    SessionInfoSize = CopyAuthSessionCommand(AuthSession, Buffer);
    Buffer += SessionInfoSize;
    WriteUnaligned32((UINT32*) AuthSessionSize, SwapBytes32(SessionInfoSize));

    // SendBuffer.InSensitive.size == ??
    UINT8 *SensitiveSize = Buffer; // do not write it yet because we don't know it
    Buffer += sizeof(UINT16);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InSensitive->sensitive.userAuth.size));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, &InSensitive->sensitive.userAuth.buffer[0], InSensitive->sensitive.userAuth.size);
    Buffer += InSensitive->sensitive.userAuth.size;
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InSensitive->sensitive.data.size));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, &InSensitive->sensitive.data.buffer[0], InSensitive->sensitive.data.size);
    Buffer += InSensitive->sensitive.data.size;
    WriteUnaligned16((UINT16*) SensitiveSize, SwapBytes16( (UINT16)( Buffer - (UINT8*) SensitiveSize - 2  ) ) ); // write it here

    *BufferInOut = Buffer;

    return EFI_SUCCESS;
}

EFI_STATUS Tpm2CreatePrimary(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    TPM2B_SENSITIVE_CREATE *InSensitive, // in
    TPM2B_PUBLIC *InPublic, TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_PUBLIC *OutPublic, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name) { // out

    EFI_STATUS Status;
    TPM2_CREATE_PRIMARY_COMMAND SendBuffer;
    TPM2_CREATE_PRIMARY_RESPONSE RecvBuffer;
    UINT8 *Buffer;
    UINT32 SendBufferSize;
    UINT32 RecvBufferSize;
    TPM_RC ResponseCode;
    UINT32 SessionInfoSize;

    SendBuffer.Header.tag = SwapBytes16(TPM_ST_SESSIONS);
    SendBuffer.Header.commandCode = SwapBytes32(TPM_CC_CreatePrimary);

    SendBuffer.PrimaryHandle = PrimaryHandle;

    Buffer = (UINT8*) &SendBuffer.AuthSession;
    SessionInfoSize = CopyAuthSessionCommand(AuthSession, Buffer);
    Buffer += SessionInfoSize;
    SendBuffer.AuthSessionSize = SwapBytes32(SessionInfoSize);

    // SendBuffer.InSensitive.size == ??
    UINT16 *SensitiveSize = (UINT16*) Buffer;
    Buffer += sizeof(UINT16);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InSensitive->sensitive.userAuth.size));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, &InSensitive->sensitive.userAuth.buffer[0], InSensitive->sensitive.userAuth.size);
    Buffer += InSensitive->sensitive.userAuth.size;
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InSensitive->sensitive.data.size));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, &InSensitive->sensitive.data.buffer[0], InSensitive->sensitive.data.size);
    Buffer += InSensitive->sensitive.data.size;
    WriteUnaligned16(SensitiveSize, SwapBytes16( (UINT16)( Buffer - (UINT8*) SensitiveSize - 2  ) ) );
    
    // SendBuffer.InPublic.size == ??
    UINT16 *PublicSize = (UINT16*) Buffer;
    Buffer += sizeof(UINT16);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InPublic->publicArea.type));
    Buffer += sizeof(UINT16);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InPublic->publicArea.nameAlg));
    Buffer += sizeof(UINT16);
    WriteUnaligned32((UINT32*) Buffer, SwapBytes32(*(UINT32*)&InPublic->publicArea.objectAttributes));
    Buffer += sizeof(UINT32);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InPublic->publicArea.authPolicy.size));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, &InPublic->publicArea.authPolicy.buffer[0], InPublic->publicArea.authPolicy.size);
    Buffer += InPublic->publicArea.authPolicy.size;
    // WriteUnaligned16(InPublic.TPMU_PUBLIC_PARAMS)
}

void Uint32ToObjectAttributes(UINT32 AttrIn, TPMA_OBJECT *AttrOut) {
    AttrOut->reserved1 = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->fixedTPM = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->stClear = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->reserved4 = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->fixedParent = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->sensitiveDataOrigin = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->userWithAuth = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->adminWithPolicy = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->reserved8_9 = (AttrIn & 0x3); AttrIn >>= 2;
    AttrOut->noDA = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->encryptedDuplication = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->reserved12_15 = (AttrIn & 0xF); AttrIn >>= 4;
    AttrOut->restricted = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->decrypt = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->sign = (AttrIn & 0x1); AttrIn >>= 1;
    AttrOut->reserved19_31 = (AttrIn & 0xd); AttrIn >>= 13;
}

EFI_STATUS DecodePublicParamsAndId_Aes(UINT8 **BufferInOut, TPM2B_PUBLIC *OutPublic) {
    UINT8 *Buffer = *BufferInOut;

    /*memcpy(&OutPublic->publicArea.parameters,
        Buffer,
        sizeof(TPMU_PUBLIC_PARMS));
    Buffer += sizeof(TPMU_PUBLIC_PARMS);*/

    TPMT_SYM_DEF_OBJECT *symDef = (TPMT_SYM_DEF_OBJECT*) Buffer;
    Buffer += sizeof(TPMT_SYM_DEF_OBJECT);
    OutPublic->publicArea.parameters.symDetail.algorithm = SwapBytes16(symDef->algorithm);
    OutPublic->publicArea.parameters.symDetail.keyBits.aes = SwapBytes16(symDef->keyBits.aes);
    OutPublic->publicArea.parameters.symDetail.mode.aes = SwapBytes16(symDef->mode.aes);

    OutPublic->publicArea.unique.sym.size = SwapBytes16(ReadUnaligned16((UINT16*) Buffer));
    Buffer += sizeof(UINT16);
    memcpy(&OutPublic->publicArea.unique.sym.buffer[0], Buffer, OutPublic->publicArea.unique.sym.size);
    Buffer += OutPublic->publicArea.unique.sym.size;

    *BufferInOut = Buffer;

    return EFI_SUCCESS;
}

EFI_STATUS DecodePublicParamsAndId_Nop(UINT8 **BufferInOut, TPM2B_PUBLIC *OutPublic) {
    return EFI_SUCCESS;
}

EFI_STATUS Tpm2CreatePrimary_Epilogue(TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION *PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_PUBLIC *OutPublic, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name, // out
    UINT8 *BufferStart, UINT8* BufferCur, // state
    EFI_STATUS(*DecodePublicParamsAndId_Callback)(UINT8**, TPM2B_PUBLIC*)) { // callback

    UINT8 *Buffer = BufferCur;

    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(OutsideInfo->size));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, &OutsideInfo->buffer[0], OutsideInfo->size);
    Buffer += OutsideInfo->size;

    WriteUnaligned32((UINT32*) Buffer, SwapBytes32(PcrSelection->count));
    Buffer += sizeof(UINT32);
    for (int i = 0; i < PcrSelection->count; i++) {
        WriteUnaligned16((UINT16*) Buffer, SwapBytes16(PcrSelection->pcrSelections[i].hash));
        Buffer += sizeof(UINT16);
        *Buffer = PcrSelection->pcrSelections[i].sizeofSelect;
        Buffer += sizeof(UINT8);
        memcpy(Buffer, &PcrSelection->pcrSelections[i].pcrSelect[0],
            PcrSelection->pcrSelections[i].sizeofSelect);
        Buffer += PcrSelection->pcrSelections[i].sizeofSelect;
    }

    UINT32 SendBufferSize;
    SendBufferSize = (UINT32)(Buffer - BufferStart);
    WriteUnaligned32((UINT32*)(BufferStart + sizeof(UINT16)), SwapBytes32(SendBufferSize));

    EFI_STATUS Status;
    TPM2_CREATE_PRIMARY_RESPONSE ResponseBuffer = {};
    UINT32 ResponseBufferSize;

    ResponseBufferSize = sizeof(ResponseBuffer);
    Status = Tpm2SubmitCommand(SendBufferSize, BufferStart, &ResponseBufferSize, (UINT8*) &ResponseBuffer);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    // TODO: write out output
	if (ResponseBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
		printf("Tpm2CreatePrimary_Epilogue - RecvBufferSize Error - %x\n", ResponseBufferSize);
		return EFI_DEVICE_ERROR;
	}
	TPM_RC ResponseCode;
    ResponseCode = SwapBytes32(ResponseBuffer.Header.responseCode);
	if (ResponseCode != TPM_RC_SUCCESS) {
		printf("Tpm2CreatePrimary_Epilogue - responseCode - %x\n", ResponseCode);
        return EFI_DEVICE_ERROR;
	}

    *ObjectHandle = SwapBytes32(ResponseBuffer.ObjectHandle);
    OutPublic->size = SwapBytes16(ResponseBuffer.OutPublic.size);
    memcpy(&OutPublic->publicArea, &ResponseBuffer.OutPublic.publicArea, OutPublic->size); // TODO: decode
    OutPublic->publicArea.type = SwapBytes16(OutPublic->publicArea.type); 
    OutPublic->publicArea.nameAlg = SwapBytes16(OutPublic->publicArea.nameAlg);
    Uint32ToObjectAttributes(SwapBytes32(*(UINT32*)&OutPublic->publicArea.objectAttributes),
        &OutPublic->publicArea.objectAttributes);
    Buffer = (UINT8*) &ResponseBuffer.OutPublic.publicArea.authPolicy;
    OutPublic->publicArea.authPolicy.size = SwapBytes16(ReadUnaligned16((UINT16*) Buffer));
    Buffer += sizeof(UINT16);
    memcpy(&OutPublic->publicArea.authPolicy.buffer[0],
        &ResponseBuffer.OutPublic.publicArea.authPolicy.buffer[0],
        OutPublic->publicArea.authPolicy.size);
    Buffer += OutPublic->publicArea.authPolicy.size;

    Status = DecodePublicParamsAndId_Callback(&Buffer, OutPublic);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    CreationData->size = SwapBytes16(ResponseBuffer.CreationData.size);
    memcpy(&CreationData->creationData, &ResponseBuffer.CreationData.creationData, CreationData->size); // TODO: decode
    CreationHash->size = SwapBytes16(ResponseBuffer.CreationHash.size);
    memcpy(&CreationHash->buffer[0], &ResponseBuffer.CreationHash.buffer[0], CreationHash->size);
    CreationTicket->tag = SwapBytes16(ResponseBuffer.CreationTicket.tag);
    CreationTicket->hierarchy = SwapBytes32(ResponseBuffer.CreationTicket.hierarchy);
    CreationTicket->digest.size = SwapBytes16(ResponseBuffer.CreationTicket.digest.size);
    memcpy(&CreationTicket->digest.buffer[0], &ResponseBuffer.CreationTicket.digest.buffer[0],
        CreationTicket->digest.size);

    return EFI_SUCCESS;
}

UINT32 ObjectAttributesToUint32(TPMA_OBJECT *ObjectAttributes) {
    UINT32 res = 0;
    res |= ObjectAttributes->reserved19_31; 
    res <<= 1; res |= ObjectAttributes->sign; 
    res <<= 1; res |= ObjectAttributes->decrypt; 
    res <<= 1; res |= ObjectAttributes->restricted; 
    res <<= 4; res |= ObjectAttributes->reserved12_15;
    res <<= 1; res |= ObjectAttributes->encryptedDuplication;
    res <<= 1; res |= ObjectAttributes->noDA;
    res <<= 2; res |= ObjectAttributes->reserved8_9;
    res <<= 1; res |= ObjectAttributes->adminWithPolicy;
    res <<= 1; res |= ObjectAttributes->userWithAuth;
    res <<= 1; res |= ObjectAttributes->sensitiveDataOrigin;
    res <<= 1; res |= ObjectAttributes->fixedParent;
    res <<= 1; res |= ObjectAttributes->reserved4;
    res <<= 1; res |= ObjectAttributes->stClear;
    res <<= 1; res |= ObjectAttributes->fixedTPM;
    res <<= 1; res |= ObjectAttributes->reserved1;
    return res;
}

EFI_STATUS Tpm2CreatePrimaryAes(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    TPM2B_SENSITIVE_CREATE *InSensitive, // in
    TPMI_ALG_HASH NameAlg, TPMA_OBJECT *ObjectAttributes, TPM2B_DIGEST *AuthPolicy, // in
    TPMI_AES_KEY_BITS KeyBits, TPMI_ALG_SYM_MODE SymMode, // in 
    TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION *PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_PUBLIC *OutPublic, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name) { // out

    TPM2_CREATE_PRIMARY_COMMAND SendBuffer;
    UINT32 SendBufferSize;
    EFI_STATUS Status;
    UINT8 *Buffer;

    Buffer = (UINT8*) &SendBuffer;
    Status = Tpm2CreatePrimary_Preamble(PrimaryHandle, AuthSession,
        InSensitive, (UINT8**) &Buffer);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    UINT8 *PublicSize = Buffer; // write it later
    Buffer += sizeof(UINT16);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(TPM_ALG_SYMCIPHER));
    Buffer += sizeof(UINT16);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(NameAlg));
    Buffer += sizeof(UINT16);
    WriteUnaligned32((UINT32*) Buffer, SwapBytes32(ObjectAttributesToUint32(ObjectAttributes)));
    Buffer += sizeof(UINT32);
    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(AuthPolicy->size));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, &AuthPolicy->buffer[0], AuthPolicy->size);
    Buffer += AuthPolicy->size;
    TPMT_SYM_DEF_OBJECT SymDetail;
    SymDetail.algorithm = SwapBytes16(TPM_ALG_AES);
    SymDetail.keyBits.aes = SwapBytes16(KeyBits);
    SymDetail.mode.aes = SwapBytes16(SymMode);
    memcpy(Buffer, &SymDetail, sizeof(SymDetail));
    Buffer += sizeof(SymDetail);
    WriteUnaligned16((UINT16*) Buffer, 0); // unique.sym
    Buffer += sizeof(UINT16);
    WriteUnaligned16((UINT16*) PublicSize, SwapBytes16( (UINT16)( Buffer - PublicSize - 2 ) )); // write it here
    printf("PublicSize: %d\n", (UINT16)( Buffer - PublicSize - 2 ));
    printf("sizeof(TPMU_PUBLIC_PARMS): %d\n", sizeof(TPMU_PUBLIC_PARMS));
    printf("sizeof(TPMS_SYMCIPHER_PARMS): %d\n", sizeof(TPMS_SYMCIPHER_PARMS));

    Status = Tpm2CreatePrimary_Epilogue(OutsideInfo, PcrSelection, // in
        ObjectHandle, OutPublic, CreationData, // out
        CreationHash, CreationTicket, Name, (UINT8*) &SendBuffer, Buffer,
        DecodePublicParamsAndId_Aes);
    return Status;
}

EFI_STATUS Tpm2CreatePrimary_PremarshalledPublic(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    TPM2B_SENSITIVE_CREATE *InSensitive, // in
    UINT8 *InPublicPremarshalled, UINT16 InPublicPremarshalledSize, // in 
    TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION *PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name) { // out

    TPM2_CREATE_PRIMARY_COMMAND SendBuffer;
    UINT32 SendBufferSize;
    EFI_STATUS Status;
    UINT8 *Buffer;

    Buffer = (UINT8*) &SendBuffer;
    Status = Tpm2CreatePrimary_Preamble(PrimaryHandle, AuthSession,
        InSensitive, (UINT8**) &Buffer);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    WriteUnaligned16((UINT16*) Buffer, SwapBytes16(InPublicPremarshalledSize));
    Buffer += sizeof(UINT16);
    memcpy(Buffer, InPublicPremarshalled, InPublicPremarshalledSize);
    Buffer += InPublicPremarshalledSize;

    TPM2B_PUBLIC IgnoreOutPublic;

    Status = Tpm2CreatePrimary_Epilogue(OutsideInfo, PcrSelection, // in
        ObjectHandle, &IgnoreOutPublic, CreationData, // out
        CreationHash, CreationTicket, Name, (UINT8*) &SendBuffer, Buffer,
        DecodePublicParamsAndId_Nop);
    return Status;
}
