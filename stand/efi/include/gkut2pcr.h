#ifndef _GKUT2PCR_H_
#define _GKUT2PCR_H_

#include <efi.h>

#include <IndustryStandard/Tpm20.h>

EFI_STATUS Tpm2PcrExtend (
    TPMI_DH_PCR         PcrHandle,
    TPML_DIGEST_VALUES  *Digests
);

#endif
