#include <efi.h>
#include <efilib.h>

#include "gkut2morc.h"


static void char8_to_char16(const CHAR8 *input, CHAR16 *output) {
    while (*input) {
        *output = *input;
        input++;
        output++;
    }
    *output = 0;
}


EFI_STATUS gkut2_request_memory_overwrite() {
    EFI_GUID morc_guid = MEMORY_OVERWRITE_REQUEST_CONTROL_GUID;
    EFI_GUID morc_lock_guid = MEMORY_OVERWRITE_REQUEST_CONTROL_LOCK_GUID;
    EFI_STATUS status;
    UINT32 morc_attr;
    UINT32 morc_lock_attr;
    UINTN size;
    UINT8 morc_value;
    UINT8 morc_lock_value;
    CHAR16 varname[64];

    char8_to_char16(MEMORY_OVERWRITE_REQUEST_CONTROL_VARNAME, &varname[0]);
    size = 1;
    status = RS->GetVariable(
        varname,
        &morc_guid,
        &morc_attr,
        &size,
        &morc_value
    );
    if (EFI_ERROR(status)) {
        printf("gkut2_request_memory_overwrite - GetVariable - MORC - 0x%lX\n", status);
        return status;
    }

    char8_to_char16(MEMORY_OVERWRITE_REQUEST_CONTROL_LOCK_VARNAME, &varname[0]);
    size = 1;
    status = RS->GetVariable(
        varname,
        &morc_lock_guid,
        &morc_lock_attr,
        &size,
        &morc_lock_value
    );
    if (EFI_ERROR(status)) {
        printf("gkut2_request_memory_overwrite - GetVariable - MORC Lock - 0x%lX\n", status);
        return status;
    }

    char8_to_char16(MEMORY_OVERWRITE_REQUEST_CONTROL_VARNAME, &varname[0]);
    size = 1;
    morc_value = 1;
    status = RS->SetVariable(
        varname,
        &morc_guid,
        morc_attr,
        size,
        &morc_value
    );
    if (EFI_ERROR(status)) {
        printf("gkut2_request_memory_overwrite - SetVariable - MORC - 0x%lX\n", status);
        return status;
    }

    char8_to_char16(MEMORY_OVERWRITE_REQUEST_CONTROL_LOCK_VARNAME, &varname[0]);
    size = 1;
    morc_lock_value = 1;
    status = RS->SetVariable(
        varname,
        &morc_lock_guid,
        morc_lock_attr,
        size,
        &morc_lock_value
    );
    if (EFI_ERROR(status)) {
        printf("gkut2_request_memory_overwrite - SetVariable - MORC Lock - 0x%lX\n", status);
        return status;
    }

    return EFI_SUCCESS;
}
