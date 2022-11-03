#include <stdio.h>


#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>

#include "gkut2tcg.h"

EFI_STATUS DummyTpm2SubmitCommand(EFI_TCG2_PROTOCOL*, UINT32, UINT8*, UINT32, UINT8*) {
    printf("DummyTpm2SubmitCommand()\n");
}

EFI_TCG2_PROTOCOL DummyTcgProtocol = {
    .SubmitCommand = DummyTpm2SubmitCommand
};

void DummyExit(void*, int, int, void*) {
    printf("BS->Exit() called.\n");
}

EFI_STATUS DummyLocateProtocol(EFI_GUID*, void*, void **Result) {
    *Result = &DummyTcgProtocol;
}

EFI_BOOT_SERVICES BS_ = {
    DummyExit,
    DummyLocateProtocol
};

EFI_BOOT_SERVICES *BS = &BS_;

void *IH;

int main() {
    printf("Hello world!\n");
    BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
}
