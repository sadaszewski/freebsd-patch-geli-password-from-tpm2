#include <efi.h>
#include <efiprot.h>

void DummyExit(void*, int, int, void*) {
    printf("BS->Exit() called.\n");
}

EFI_BOOT_SERVICES BS_ = {
    .Exit = DummyExit
};

EFI_BOOT_SERVICES *BS = &BS_;

