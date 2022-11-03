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
    TPM2B_MAX_BUFFER      OutData;
    TPM2B_IV              IvOut;
} TPM2_ENCRYPT_DECRYPT_RESPONSE;

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
    TPM2B_SENSITIVE_CREATE  InSensitive;
    TPM2B_PUBLIC            InPublic;
    TPM2B_DATA              OutsideInfo;
    TPML_PCR_SELECTION      PcrSelection;
} TPM2_CREATE_PRIMARY_COMMAND;

typedef struct {
    TPM2_RESPONSE_HEADER    Header;
    TPM_HANDLE              ObjectHandle;
    TPM2B_PUBLIC            OutPublic;
    TPM2B_CREATION_DATA     CreationData;
    TPM2B_DIGEST            CreationHash;
    TPMT_TK_CREATION        CreationTicket;
    TPM2B_NAME              Name;
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

    OutData->size = SwapBytes16(RecvBuffer.OutData.size);
    if (OutData->size > MAX_DIGEST_BUFFER) {
		printf("Tpm2EncryptDecrypt - OutData->size error %x\n", OutData->size);
		Status = EFI_DEVICE_ERROR;
		goto Done;
    }
    memcpy(&OutData->buffer[0], &RecvBuffer.OutData.buffer[0], OutData->size);

    Buffer = ((UINT8*) &RecvBuffer.OutData) + sizeof(UINT16) + OutData->size;
    OutIv->size = SwapBytes16(ReadUnaligned16((UINT16*) Buffer));
    Buffer += sizeof(UINT16);
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
