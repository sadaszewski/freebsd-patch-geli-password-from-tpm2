#include <efi.h>
#include <stdio.h>
#include <IndustryStandard/Tpm20.h>
#include <assert.h>

#include "gkut2tcg.h"
#include "gkut2dec.h"
#include "gkut2auth.h"

void mock_tpm2_init();

void mock_tpm2_api_init();

void test_01_load_ext_public() {
    printf("======= test_01_load_ext_public() ========\n");
    FILE *f = fopen("/tmp/test-ext-public/ext-public", "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("sz: %llu\n", sz);
    TPMT_PUBLIC buffer;
    assert(fread((char*) &buffer, sz, 1, f) == 1);
    printf("type: 0x%08X\n", SwapBytes16(buffer.type));
    printf("nameAlg: 0x%08X\n", SwapBytes16(buffer.nameAlg));
    printf("objectAttributes: 0x%08X\n", SwapBytes32(*(UINT32*)&buffer.objectAttributes));
    assert(SwapBytes16(buffer.type) == TPM_ALG_SYMCIPHER);
    assert(SwapBytes16(buffer.nameAlg) == TPM_ALG_SHA256);
    UINT32 a = SwapBytes32(*(UINT32*)&buffer.objectAttributes);
    assert(a & (1 << 1));
    assert(a & (1 << 4));
    assert(a & (1 << 5));
    assert(a & (1 << 6));
    assert(a & (1 << 17));
    assert(a & (1 << 18));
    printf("Success!\n");
}

void test_02_load_and_create() {
    printf("======== test_02_load_and_create() =======\n"); 
    FILE *f = fopen("/tmp/test-ext-public/ext-public", "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("sz: %llu\n", sz);
    TPMT_PUBLIC buffer;
    assert(fread((char*) &buffer, sz, 1, f) == 1);

	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;
    TPMI_SH_AUTH_SESSION SessionHandle;
    EFI_STATUS Status;
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
        .nonce = { .size = 0 },
        .sessionAttributes = 0,
        .hmac = { .size = 0 }
    };
    TPM2B_SENSITIVE_CREATE InSensitive = {
        .size = 2 * sizeof(UINT16),
        .sensitive = {
            .userAuth = { .size = 0 },
            .data = { .size = 0 }
        }
    };
    TPM2B_DATA OutsideInfo = { .size = 0 };
    TPML_PCR_SELECTION PcrSelection = {
        .count = 0
    };
    TPM_HANDLE ObjectHandle;
    TPM2B_CREATION_DATA CreationData;
    TPM2B_DIGEST CreationHash;
    TPMT_TK_CREATION CreationTicket;
    TPM2B_NAME Name;

    Status = Tpm2CreatePrimary_PremarshalledPublic(PrimaryHandle, &AuthSession, // in
        &InSensitive, // in
        (UINT8*) &buffer, (UINT16) sz, // in 
        &OutsideInfo, &PcrSelection, // in
        &ObjectHandle, &CreationData, // out
        &CreationHash, &CreationTicket, &Name); // out
    if (EFI_ERROR(Status)) {
		printf("Tpm2CreatePrimary_PremarshalledPublic() failed - 0x%lx.\n", Status);
		return;
    }

    printf("ObjectHandle: 0x%08X\n", ObjectHandle);

    printf("Success!!!\n");
}

void test_03_load_secondary() {
    printf("======== test_03_load_secondary() =======\n"); 
    FILE *f = fopen("/tmp/test-ext-public/sec-pub", "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    TPM2B_PUBLIC pub;
    pub.size = ftell(f) - 2;
    fseek(f, 2, SEEK_SET);
    printf("pub.size: %d\n", pub.size);
    assert(fread((char*) &pub.publicArea, pub.size, 1, f) == 1);
    fclose(f);
 
    f = fopen("/tmp/test-ext-public/sec-priv", "rb");
    assert(f != NULL);
    fseek(f, 0, SEEK_END);
    TPM2B_PRIVATE priv;
    priv.size = ftell(f) - 2;
    fseek(f, 2, SEEK_SET);
    printf("priv.size: %d\n", priv.size);
    assert(fread((char*) &priv.buffer[0], priv.size, 1, f) == 1);
    fclose(f);

	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;
    TPMI_SH_AUTH_SESSION SessionHandle;
    EFI_STATUS Status;
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

    TPMI_RH_HIERARCHY ParentHandle = 0x81000000;
    TPMS_AUTH_COMMAND AuthSession = {
        .sessionHandle = SessionHandle,
        .nonce = { .size = 0 },
        .sessionAttributes = 0,
        .hmac = { .size = 0 }
    };
    TPM_HANDLE ObjectHandle;
    TPM2B_NAME Name;

    Status = Tpm2Load(ParentHandle, &AuthSession,
        (UINT8*) &priv.buffer[0], priv.size,
        (UINT8*) &pub.publicArea, pub.size, 
        &ObjectHandle, &Name);
    if (EFI_ERROR(Status)) {
		printf("Tpm2Load() failed - 0x%lx.\n", Status);
		return;
    }

    printf("ObjectHandle: 0x%08X\n", ObjectHandle);

    printf("Success!!!\n");
}

int main() {
    mock_tpm2_init();
    mock_tpm2_api_init();
    //test_01_load_ext_public();
    //test_02_load_and_create();
    test_03_load_secondary();
}
