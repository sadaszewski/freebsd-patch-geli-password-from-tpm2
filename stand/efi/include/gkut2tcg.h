#ifndef _GKUT2_TCG_H_
#define _GKUT2_TCG_H_

#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>

static UINT16 SwapBytes16 (UINT16 Value) {
	return (UINT16) ((Value<< 8) | (Value>> 8));
}

static UINT32 SwapBytes32 (UINT32 Value) {
	UINT32  LowerBytes;
	UINT32  HigherBytes;

	LowerBytes  = (UINT32) SwapBytes16 ((UINT16) Value);
	HigherBytes = (UINT32) SwapBytes16 ((UINT16) (Value >> 16));
	return (LowerBytes << 16 | HigherBytes);
}

static UINT16 ReadUnaligned16 (const UINT16 *Buffer) {
	if (Buffer == NULL) {
		printf("Buffer is NULL in ReadUnaligned16\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT16) -1);
	}
	return *Buffer;
}

static UINT32 ReadUnaligned32 (const UINT32 *Buffer) {
 	if (Buffer == NULL) {
		printf("Buffer is NULL in ReadUnaligned32\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT32) -1);
	}
	return *Buffer;
}

static UINT16 WriteUnaligned16 (UINT16 *Buffer, UINT16 Value) {
	if (Buffer == NULL) {
		printf("NULL buffer passed to WriteUnaligned16\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT16) -1);
	}

	return (*Buffer = Value);
}

static UINT32 WriteUnaligned32 (UINT32 *Buffer, UINT32 Value) {
	if (Buffer == NULL) {
		printf("Buffer is NULL in WriteUnaligned32\n");
		BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
		return ((UINT32) -1);
	}

	return (*Buffer = Value);
}

EFI_STATUS Tpm2SubmitCommand (
	UINT32	InputParameterBlockSize,
	UINT8	*InputParameterBlock,
	UINT32	*OutputParameterBlockSize,
	UINT8	*OutputParameterBlock);

UINT32 CopyAuthSessionCommand (
	TPMS_AUTH_COMMAND		*AuthSessionIn,
	UINT8					*AuthSessionOut
);

#endif // _GKUT2_TCG_H_
