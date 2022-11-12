#include <efi.h>
#include <efirng.h>

#include <Protocol/Tcg2Protocol.h>

#include <stdio.h>

EFI_TCG2_PROTOCOL *DummyTcgProtocol;
EFI_RNG_PROTOCOL *DummyRngProtocol;

EFI_STATUS DummyLocateProtocol(EFI_GUID *guid, void*, void **Result) {
    EFI_GUID rng_guid = EFI_RNG_PROTOCOL_GUID;
    EFI_GUID tcg_guid = EFI_TCG2_PROTOCOL_GUID;

    if (memcmp(guid, &tcg_guid, sizeof(EFI_GUID)) == 0) {
        printf("DummyLocateProtocol() TCG2, DummyTcgProtocol: 0x%08X\n", DummyTcgProtocol);
        *Result = DummyTcgProtocol;
    } else if (memcmp(guid, &rng_guid, sizeof(EFI_GUID)) == 0) {
        printf("DummyLocateProtocol() RNG\n");
        *Result = DummyRngProtocol;
    } else {
        return EFI_UNSUPPORTED;
    }

    if (*Result == NULL) {
        return EFI_UNSUPPORTED;
    }

    return EFI_SUCCESS;
}

extern EFI_BOOT_SERVICES *BS;
void *IH;
