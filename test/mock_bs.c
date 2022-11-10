#include <efi.h>
#include <efiprot.h>
#include <efilib.h>
#include <crypto/sha2/sha256.h>
#include <stdio.h>

void DummyExit(void*, int, int, void*) {
    printf("BS->Exit() called.\n");
}

EFI_BOOT_SERVICES BS_ = {
    .Exit = DummyExit
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
