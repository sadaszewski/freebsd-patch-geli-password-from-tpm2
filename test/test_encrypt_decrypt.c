#include <stdio.h>
#include <assert.h>

#include "gkut2tcg.h"

void mock_tpm2_init();

EFI_STATUS Tpm2ContextLoad(UINT64 Sequence, TPMI_DH_CONTEXT SavedHandle, TPMI_RH_HIERARCHY Hierarchy,
    TPM2B_CONTEXT_DATA *ContextBlob, TPMI_DH_CONTEXT *LoadedHandle);

static UINT16 SwapBytes16_ (UINT16 Value) {
	return (UINT16) ((Value<< 8) | (Value>> 8));
}

static UINT32 SwapBytes32_ (UINT32 Value) {
	UINT32  LowerBytes;
	UINT32  HigherBytes;

	LowerBytes  = (UINT32) SwapBytes16 ((UINT16) Value);
	HigherBytes = (UINT32) SwapBytes16 ((UINT16) (Value >> 16));
	return (LowerBytes << 16 | HigherBytes);
}

static UINT64 SwapBytes64_(UINT64 Value) {
    UINT64 LowerBytes;
    UINT64 HigherBytes;
    LowerBytes = (UINT64) SwapBytes32((UINT32) Value);
    HigherBytes = (UINT64) SwapBytes32((UINT32) (Value >> 32));
    return (LowerBytes << 32 | HigherBytes);
}

void test_01_decrypt() {
    FILE *f = fopen("/tmp/test2.ctx", "rb");
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f) - 8;
    printf("sz: %llu\n", sz);
    assert(sz < sizeof(TPMS_CONTEXT));
    fseek(f, 8, SEEK_SET);
    TPMI_RH_HIERARCHY Hierarchy;
    TPMI_DH_CONTEXT SavedHandle;
    UINT64 Sequence;
    UINT16 BlobSize;
    assert (fread(&Hierarchy, 4, 1, f) == 1);
    assert(fread(&SavedHandle, 4, 1, f) == 1);
    assert(fread(&Sequence, 8, 1, f) == 1);
    assert(fread(&BlobSize, 2, 1, f) == 1);
    BlobSize = SwapBytes16_(BlobSize);
    printf("BlobSize: %d\n", BlobSize);
    TPM2B_CONTEXT_DATA ContextBlob;
    assert(fread(&ContextBlob.buffer[0], BlobSize, 1, f) == 1);
    ContextBlob.size = BlobSize;
    fclose(f);
    printf("sizeof(TPMS_CONTEXT): %d\n", sizeof(TPMS_CONTEXT));
    Sequence = SwapBytes64_(Sequence);
    SavedHandle = SwapBytes32_(SavedHandle);
    Hierarchy = SwapBytes32_(Hierarchy);
    printf("Sequence: 0x%llX\n", Sequence);
    printf("SavedHandle: 0x%X\n", SavedHandle);
    printf("Hierarchy: 0x%X\n", Hierarchy);
    printf("BlobSize: %d\n", BlobSize);
    TPMI_DH_CONTEXT LoadedHandle;
    EFI_STATUS Status;
    Status = Tpm2ContextLoad(Sequence, SavedHandle,
        Hierarchy, &ContextBlob, &LoadedHandle);
    printf("Status: 0x%X, LoadedHandle: 0x%X\n", Status, LoadedHandle);
}

int main() {
    printf("Hello world!\n");
    mock_tpm2_init();
    test_01_decrypt();
    BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
}
