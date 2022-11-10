/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2021 Stanislaw R. Adaszewski
 * All rights reserved.
 *
 *	@(#)tpm2cpm.c	13.0 (Villeneuve) 11/27/21
 */

#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>

#include "gkut2tcg.h"


static EFI_GUID mEfiTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;
static EFI_TCG2_PROTOCOL *mTcg2Protocol = NULL;


EFI_STATUS Tpm2SubmitCommand (
	UINT32	InputParameterBlockSize,
	UINT8	*InputParameterBlock,
	UINT32	*OutputParameterBlockSize,
	UINT8	*OutputParameterBlock) {
	
	EFI_STATUS				Status;
	TPM2_RESPONSE_HEADER	*Header;

	if (mTcg2Protocol == NULL) {
		Status = BS->LocateProtocol (&mEfiTcg2ProtocolGuid, NULL, (VOID **) &mTcg2Protocol);
		if (EFI_ERROR (Status)) {
			//
			// Tcg2 protocol is not installed. So, TPM2 is not present.
			//
			printf("Tpm2SubmitCommand - Tcg2 - %lu\n", Status);
			return EFI_NOT_FOUND;
		}
	}
	
	//
	// Assume when Tcg2 Protocol is ready, RequestUseTpm already done.
	//
	Status = mTcg2Protocol->SubmitCommand (
		mTcg2Protocol,
		InputParameterBlockSize,
		InputParameterBlock,
		*OutputParameterBlockSize,
		OutputParameterBlock
	);
	if (EFI_ERROR (Status)) {
		return Status;
	}
	Header = (TPM2_RESPONSE_HEADER *)OutputParameterBlock;
	*OutputParameterBlockSize = SwapBytes32 (Header->paramSize);

	return EFI_SUCCESS;
}


UINT32 CopyAuthSessionCommand (
	TPMS_AUTH_COMMAND		*AuthSessionIn,
	UINT8					*AuthSessionOut
) {
	UINT8  *Buffer;

	Buffer = (UINT8 *)AuthSessionOut;

	//
	// Add in Auth session
	//
	if (AuthSessionIn != NULL) {
		//  sessionHandle
		WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(AuthSessionIn->sessionHandle));
		Buffer += sizeof(UINT32);

		// nonce
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->nonce.size));
		Buffer += sizeof(UINT16);

		memcpy (Buffer, AuthSessionIn->nonce.buffer, AuthSessionIn->nonce.size);
		Buffer += AuthSessionIn->nonce.size;

		// sessionAttributes
		*(UINT8 *)Buffer = *(UINT8 *)&AuthSessionIn->sessionAttributes;
		Buffer++;

		// hmac
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (AuthSessionIn->hmac.size));
		Buffer += sizeof(UINT16);

		memcpy (Buffer, AuthSessionIn->hmac.buffer, AuthSessionIn->hmac.size);
		Buffer += AuthSessionIn->hmac.size;
	} else {
		//  sessionHandle
		WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32(TPM_RS_PW));
		Buffer += sizeof(UINT32);

		// nonce = nullNonce
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
		Buffer += sizeof(UINT16);

		// sessionAttributes = 0
		*(UINT8 *)Buffer = 0x00;
		Buffer++;

		// hmac = nullAuth
		WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16(0));
		Buffer += sizeof(UINT16);
	}

	return (UINT32)((UINTN)Buffer - (UINTN)AuthSessionOut);
}


EFI_STATUS Tpm2LocateProtocol() {
    EFI_STATUS				Status;

	if (mTcg2Protocol == NULL) {
		Status = BS->LocateProtocol (&mEfiTcg2ProtocolGuid, NULL, (VOID **) &mTcg2Protocol);
		if (EFI_ERROR (Status)) {
			return EFI_NOT_FOUND;
		}
	}

	return EFI_SUCCESS;
}
