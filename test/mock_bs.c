#include <efi.h>
#include <efiprot.h>
#include <efilib.h>
#include <crypto/sha2/sha256.h>
#include <stdio.h>

EFI_STATUS DummyLocateProtocol(EFI_GUID *guid, void*, void **Result); // mock_locate_protocol.c

void DummyExit(void*, int, int, void*) {
    printf("BS->Exit() called.\n");
}

EFI_BOOT_SERVICES BS_ = {
    .Exit = DummyExit,
    .LocateProtocol = DummyLocateProtocol
};

EFI_BOOT_SERVICES *BS = &BS_;

time_t getsecs() {
    time_t res = time(NULL);
    return res;
}

void efi_exit(EFI_STATUS status) {
    exit(status);
}

int SHA256_Init(SHA256_CTX*) {
    printf("SHA256_Init - mock implementation does nothing\n");
    return 0;
}

int SHA256_Update(SHA256_CTX*, const UINT8*, UINT64) {
    printf("SHA256_Update - mock implementation does nothing\n");
    return 0;
}

int SHA256_Final(UINT8*, SHA256_CTX*) {
    printf("SHA256_Final - mock implementation does nothing\n");
    return 0;
}

EFI_STATUS DummyGetTime(EFI_TIME *Time, EFI_TIME_CAPABILITIES *Capabilities) {
    printf("RS->GetTime - mock implementation does nothing\n");
    return EFI_UNSUPPORTED;
}

EFI_RUNTIME_SERVICES RS_ = {
    .GetTime = DummyGetTime
};

EFI_RUNTIME_SERVICES *RS = &RS_;

time_t from_efi_time(EFI_TIME *ETime) {
    printf("from_efi_time - mock implementation does nothing\n");
    return 0;
}
