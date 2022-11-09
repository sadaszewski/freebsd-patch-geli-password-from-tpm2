#include <efi.h>
#include <IndustryStandard/Tpm20.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

TPMI_ALG_HASH gkut2_resolve_hash_alg_name(const char *name) {
	if (strcasecmp(name, "sha1") == 0)
		return TPM_ALG_SHA1;
	else if (strcasecmp(name, "sha256") == 0)
		return TPM_ALG_SHA256;
	else if (strcasecmp(name, "sha384") == 0)
		return TPM_ALG_SHA384;
	else if (strcasecmp(name, "sha512") == 0)
		return TPM_ALG_SHA512;
	else
		return (TPMI_ALG_HASH) strtol(name, NULL, 16);
}

EFI_STATUS tpm2_parse_efivar_policy_spec(char *policy_pcr, TPMI_ALG_HASH *algHash, BYTE *pcrSelect, BYTE *sizeofSelect) {
	char *p;
	char *pi;
	char ch;
	UINT32 pcr_index;

	if (policy_pcr == NULL || algHash == NULL || pcrSelect == NULL || sizeofSelect == NULL)
		return EFI_INVALID_PARAMETER;

	bzero(pcrSelect, PCR_SELECT_MAX);
	*sizeofSelect = PCR_SELECT_MIN;

	p = policy_pcr;
	while (isspace(*p)) {
		p++;
	}
	pi = p;
	while (1) {
		ch = *pi;
		if (ch == ':') {
			*pi = '\0';
			if (strchr(p, ' ') != NULL)
				*strchr(p, ' ') = '\0';
			*algHash = gkut2_resolve_hash_alg_name(p);
			p = pi + 1;
		} else if (ch == ',' || ch == '\0') {
			*pi = '\0';
			pcr_index = strtol(p, NULL, 10);
			if (pcr_index / 8 >= PCR_SELECT_MAX) {
				goto pcr_index_too_large;
			}
			pcrSelect[(pcr_index / 8)] |= (1 << (pcr_index % 8));
			if (1 + pcr_index / 8 > *sizeofSelect) {
				*sizeofSelect = 1 + pcr_index / 8;
			}
pcr_index_too_large:
			p = pi + 1;
		}
		if (ch == '\0') {
			break;
		}
		pi++;
	}

	(void)free(policy_pcr);

	return EFI_SUCCESS;
}
