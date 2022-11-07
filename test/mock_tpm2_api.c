
#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <IndustryStandard/Tpm20.h>
#include <Protocol/Tcg2Protocol.h>

int mock_submit_command(UINT32, UINT8*, UINT32, UINT8*);

EFI_STATUS DummyHandleProtocol(void*, EFI_GUID*, void**); // mock_simplefs.c

EFI_STATUS DummyTpm2SubmitCommand(EFI_TCG2_PROTOCOL*, UINT32 InSize, UINT8 *InBuffer, UINT32 OutSize, UINT8 *OutBuffer) {
    printf("DummyTpm2SubmitCommand()\n");
    int res = mock_submit_command(InSize, InBuffer, OutSize, OutBuffer);
    if (res == 0) {
        return EFI_SUCCESS;
    } else {
        return EFI_DEVICE_ERROR;
    }
}

EFI_TCG2_PROTOCOL DummyTcgProtocol = {
    .SubmitCommand = DummyTpm2SubmitCommand
};

void DummyExit(void*, int, int, void*) {
    printf("BS->Exit() called.\n");
}

EFI_STATUS DummyLocateProtocol(EFI_GUID*, void*, void **Result) {
    *Result = &DummyTcgProtocol;
    return EFI_SUCCESS;
}

EFI_BOOT_SERVICES BS_ = {
    DummyExit,
    DummyLocateProtocol,
    DummyHandleProtocol
};

EFI_BOOT_SERVICES *BS = &BS_;

void *IH;
