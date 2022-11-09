#ifndef _GKUT2_PARSE_H_
#define _GKUT2_PARSE_H_

#include <efi.h>

#include <IndustryStandard/Tpm20.h>

TPMI_ALG_HASH gkut2_resolve_hash_alg_name(const char *name);

EFI_STATUS tpm2_parse_efivar_policy_spec(char *policy_pcr, TPMI_ALG_HASH *algHash, BYTE *pcrSelect, BYTE *sizeofSelect);

#endif
