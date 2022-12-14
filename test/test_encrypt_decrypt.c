#include <stdio.h>
#include <assert.h>

#include "gkut2tcg.h"

void mock_tpm2_init();

void mock_tpm2_api_init();

EFI_STATUS Tpm2ContextLoad(UINT64 Sequence, TPMI_DH_CONTEXT SavedHandle, TPMI_RH_HIERARCHY Hierarchy,
    TPM2B_CONTEXT_DATA *ContextBlob, TPMI_DH_CONTEXT *LoadedHandle);

EFI_STATUS Tpm2ContextSave(TPMI_DH_CONTEXT SaveHandle, TPMS_CONTEXT *Context);

EFI_STATUS Tpm2CreatePrimaryAes(TPMI_RH_HIERARCHY PrimaryHandle, TPMS_AUTH_COMMAND *AuthSession, // in
    TPM2B_SENSITIVE_CREATE *InSensitive, // in
    TPMI_ALG_HASH NameAlg, TPMA_OBJECT *ObjectAttributes, TPM2B_DIGEST *AuthPolicy, // in
    TPMI_AES_KEY_BITS KeyBits, TPMI_ALG_SYM_MODE SymMode, // in 
    TPM2B_DATA *OutsideInfo, TPML_PCR_SELECTION *PcrSelection, // in
    TPM_HANDLE *ObjectHandle, TPM2B_PUBLIC *OutPublic, TPM2B_CREATION_DATA *CreationData, // out
    TPM2B_DIGEST *CreationHash, TPMT_TK_CREATION *CreationTicket, TPM2B_NAME *Name); // out

UINT32 ObjectAttributesToUint32(TPMA_OBJECT *ObjectAttributes);

EFI_STATUS Tpm2EncryptDecrypt(
    TPMI_DH_OBJECT        KeyHandle,
    TPMS_AUTH_COMMAND     *AuthSession,
    TPMI_YES_NO           Decrypt,
    TPMI_ALG_SYM_MODE     Mode,
    TPM2B_IV              *IvIn,
    TPM2B_MAX_BUFFER      *InData,
    TPM2B_MAX_BUFFER      *OutData,
    TPM2B_IV              *OutIv);

EFI_STATUS Tpm2StartAuthSession (
	TPMI_DH_OBJECT			TpmKey,
	TPMI_DH_ENTITY			Bind,
	TPM2B_NONCE			*NonceCaller,
	TPM2B_ENCRYPTED_SECRET	*Salt,
	TPM_SE					SessionType,
	TPMT_SYM_DEF			*Symmetric,
	TPMI_ALG_HASH			AuthHash,
	TPMI_SH_AUTH_SESSION	*SessionHandle,
	TPM2B_NONCE			*NonceTPM);

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

void test_01_save_context() {
    printf("======== test_01_save_context() ========\n");
    TPMS_CONTEXT Context;
    EFI_STATUS Status;
    Status = Tpm2ContextSave(0x80000000, &Context);
    assert(Status == EFI_SUCCESS);
    FILE *f = fopen("/tmp/test-save-context.raw", "wb");
    assert(fwrite(&Context, sizeof(UINT64) + sizeof(UINT32) * 2 + sizeof(UINT16) + Context.contextBlob.size, 1, f) == 1);
    fclose(f);
    printf("Context.sequence: 0x%llX\n", Context.sequence);
    printf("Context.savedHandle: 0x%llX\n", Context.savedHandle);
    printf("Context.hierarchy: 0x%llX\n", Context.hierarchy);
    printf("Context.contextBlob.size: %d\n", Context.contextBlob.size);
    printf("Success!\n");
}

void test_02_load_context() {
    printf("======== test_02_load_context() ========\n");
    FILE *f = fopen("/tmp/test-save-context.raw", "rb");
    UINT64 Sequence;
    UINT32 SavedHandle;
    UINT32 Hierarchy;
    UINT16 BlobSize;
    TPM2B_CONTEXT_DATA ContextBlob;
    assert(fread(&Sequence, 8, 1, f) == 1);
    assert(fread(&SavedHandle, 4, 1, f) == 1);
    assert(fread(&Hierarchy, 4, 1, f) == 1);
    assert(fread(&BlobSize, 2, 1, f) == 1);
    printf("Sequence: 0x%llX\n", Sequence);
    printf("SavedHandle: 0x%X\n", SavedHandle);
    printf("Hierarchy: 0x%X\n", Hierarchy);
    printf("BlobSize: %d\n", BlobSize);
    ContextBlob.size = BlobSize;
    assert(fread(&ContextBlob.buffer[0], BlobSize, 1, f) == 1);
    EFI_STATUS Status;
    TPMI_DH_CONTEXT LoadedHandle;
    Status = Tpm2ContextLoad(Sequence, SavedHandle, Hierarchy, &ContextBlob, &LoadedHandle);
    assert(Status == EFI_SUCCESS);
    printf("LoadedHandle: 0x%X\n", LoadedHandle);
}

void test_03_decrypt() {
    printf("======== test_03_decrypt() ========\n");
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
    printf("ContextBlob.buffer: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", ContextBlob.buffer[i]);
    }
    printf("\n");
    TPMS_CONTEXT_DATA *ContextData = (TPMS_CONTEXT_DATA*) &ContextBlob.buffer[0];
    printf("ContextData->integrity.size: %d\n", ContextData->integrity.size);
    printf("----> %d\n", ((TPM2B_CONTEXT_SENSITIVE*) (((UINT8*) ContextData) + 2))->size);
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

void test_04_create_primary_aes() {
    printf("======= test_04_create_primary_aes() =======\n");

    EFI_STATUS Status;

	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;
    TPMI_SH_AUTH_SESSION SessionHandle;
	Status = Tpm2StartAuthSession (
	    TPM_RH_NULL,	// TpmKey
	    TPM_RH_NULL,	// Bind
	    &NonceCaller,
	    &Salt,
	    TPM_SE_HMAC,	// SessionType
	    &Symmetric,
	    TPM_ALG_SHA256,	//AuthHash
	    &SessionHandle,
	    &NonceTPM
	);
	if (EFI_ERROR(Status)) {
		printf("Tpm2StartAuthSession() failed - 0x%lx.\n", Status);
		return;
	}

    TPMI_RH_HIERARCHY PrimaryHandle = TPM_RH_OWNER;
	TPMS_AUTH_COMMAND AuthSession = {
	    .sessionHandle = SessionHandle,
	    .nonce = { 0 },
	    .sessionAttributes = 0,
	    .hmac = { 0 }
	};
    TPM2B_SENSITIVE_CREATE InSensitive = {
        .size = 2 * sizeof(UINT16),
        .sensitive = {
            .userAuth = { .size = 0 },
            .data = { .size = 0 }
        }
    };
    TPMI_ALG_HASH NameAlg = TPM_ALG_SHA256;
    TPMA_OBJECT ObjectAttributes = {
       .fixedTPM = 1,
       .fixedParent = 1,
       .sign = 1,
       .sensitiveDataOrigin = 1,
       .userWithAuth = 1
    };
    printf("ObjectAttributes = 0x%08X\n", ObjectAttributesToUint32(&ObjectAttributes));
    TPM2B_DIGEST AuthPolicy = {
        .size = 0
    };
    TPMI_AES_KEY_BITS KeyBits = 128;
    TPMI_ALG_SYM_MODE SymMode = TPM_ALG_CFB;
    TPM2B_DATA OutsideInfo = {
        .size = 0
    };
    TPML_PCR_SELECTION PcrSelection = { 
        .count = 0
    };

    TPM_HANDLE ObjectHandle;
    TPM2B_PUBLIC OutPublic;
    TPM2B_CREATION_DATA CreationData;
    TPM2B_DIGEST CreationHash;
    TPMT_TK_CREATION CreationTicket;
    TPM2B_NAME Name;

    Status = Tpm2CreatePrimaryAes(PrimaryHandle, &AuthSession, // in
        &InSensitive, // in
        NameAlg, &ObjectAttributes, &AuthPolicy, // in
        KeyBits, SymMode, // in 
        &OutsideInfo, &PcrSelection, // in
        &ObjectHandle, &OutPublic, &CreationData, // out
        &CreationHash, &CreationTicket, &Name);
    if (EFI_ERROR(Status)) {
        printf("Tpm2CreatePrimaryAes() failed - 0x%lx\n", Status);
        return;
    }

    printf("ObjectHandle: 0x%08X\n", ObjectHandle);
    printf("OutPublic.nameAlg: 0x%04X\n", OutPublic.publicArea.nameAlg);
    printf("OutPublic.objectAttributes: %d %d\n",
        OutPublic.publicArea.objectAttributes.fixedTPM,
        OutPublic.publicArea.objectAttributes.fixedParent
        );

    printf("authPolicy.size: %d\n", OutPublic.publicArea.authPolicy.size);

    printf("symDef.algorithm: 0x%04X\n", OutPublic.publicArea.parameters.symDetail.algorithm);
    printf("symDef.keyBits.aea: 0x%04X\n", OutPublic.publicArea.parameters.symDetail.keyBits.aes);
    printf("symDef.mode.aes: 0x%04X\n", OutPublic.publicArea.parameters.symDetail.mode.aes);

    printf("Success!!!\n");
}

void test_05_encrypt() {
    printf("======= test_05_encrypt() =======\n");

    EFI_STATUS Status;

	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;
    TPMI_SH_AUTH_SESSION SessionHandle;
	Status = Tpm2StartAuthSession (
	    TPM_RH_NULL,	// TpmKey
	    TPM_RH_NULL,	// Bind
	    &NonceCaller,
	    &Salt,
	    TPM_SE_HMAC,	// SessionType
	    &Symmetric,
	    TPM_ALG_SHA256,	//AuthHash
	    &SessionHandle,
	    &NonceTPM
	);
	if (EFI_ERROR(Status)) {
		printf("Tpm2StartAuthSession() failed - 0x%lx.\n", Status);
		return;
	}

    TPMI_DH_OBJECT KeyHandle = 0x80000000;
    TPMS_AUTH_COMMAND AuthSession = {
        .sessionHandle = SessionHandle,
        .nonce = { 0 },
        .sessionAttributes = 0,
        .hmac = { 0 }
    };
    TPMI_YES_NO Decrypt = 0;
    TPMI_ALG_SYM_MODE Mode = TPM_ALG_CFB;
    TPM2B_IV InIv = { .size = 16 };
    TPM2B_MAX_BUFFER InData = { .size = 6, .buffer = "foobar" };
    TPM2B_MAX_BUFFER OutData;
    TPM2B_IV OutIv;
 
    Status = Tpm2EncryptDecrypt(
        KeyHandle,
        &AuthSession,
        Decrypt,
        Mode,
        &InIv,
        &InData,
        &OutData,
        &OutIv);
    if (EFI_ERROR(Status)) {
        printf("Tpm2EncryptDecrypt() error - 0x%lX\n", Status);
        return;
    }

    printf("OutData.size: %d\n", OutData.size);
    printf("Encrypted data:\n");
    for (UINT16 i = 0; i < OutData.size; i++) {
        printf("%02X ", OutData.buffer[i]);
    }
    printf("\n");

    printf("Success!!!\n");
}

int main() {
    printf("Hello world!\n");
    mock_tpm2_init();
    mock_tpm2_api_init();
    //test_01_save_context();
    //test_02_load_context();
    //test_03_decrypt();
    test_04_create_primary_aes();
    // test_05_encrypt();
    BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
}
