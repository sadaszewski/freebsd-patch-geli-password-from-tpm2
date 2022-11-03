
#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>

void mock_submit_command(UINT32, UINT8*, UINT32, UINT8*);

EFI_STATUS DummyTpm2SubmitCommand(EFI_TCG2_PROTOCOL*, UINT32 InSize, UINT8 *InBuffer, UINT32 OutSize, UINT8 *OutBuffer) {
    printf("DummyTpm2SubmitCommand()\n");
    mock_submit_command(InSize, InBuffer, OutSize, OutBuffer);
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
