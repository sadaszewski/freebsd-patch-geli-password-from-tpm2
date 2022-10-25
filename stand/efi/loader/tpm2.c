/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2021 Stanislaw R. Adaszewski
 * All rights reserved.
 *
 *	@(#)tpm2cpm.c	13.0 (Villeneuve) 11/27/21
 */


#include "efitpm2.h"
#include "efitpm2nv.h"

#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <Protocol/Tcg2Protocol.h>

#include "geliboot.h"

#include <crypto/sha2/sha256.h>


#define TPM2_PAUSE_BEFORE_EXIT 10
#define TPM2_AUTOBOOT_TIMEOUT 0


static TPMS_PCR_SELECTION pcr_selection;
static TPMI_RH_NV_INDEX nvindex;
static UINT8 try_retrieve_passphrase_from_tpm;
static TPM2B_MAX_BUFFER passphrase_from_nvindex;
static UINT8 passphrase_was_retrieved;


TPMI_ALG_HASH tpm2_parse_efivar_policy_spec(BYTE *pcrSelect, BYTE *sizeofSelect);


static char *efi_freebsd_getenv_helper(const char *name) {
	char *freeme = NULL;
	UINTN len = 0;

	if (efi_freebsd_getenv(name, NULL, &len) == EFI_BUFFER_TOO_SMALL) {
		freeme = malloc(len + 1);
		if (freeme == NULL)
			return NULL;
		if (efi_freebsd_getenv(name, freeme, &len) == EFI_SUCCESS) {
			freeme[len] = '\0';
			return freeme;
		} else {
			(void)free(freeme);
			return NULL;
		}
	}

	return NULL;
}


static TPMI_ALG_HASH resolve_hash_alg_name(const char *name) {
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


TPMI_ALG_HASH tpm2_parse_efivar_policy_spec(BYTE *pcrSelect, BYTE *sizeofSelect) {
	char *policy_pcr = NULL;
	char *p;
	char *pi;
	char ch;
	UINT32 pcr_index;
	TPMI_ALG_HASH alg;

	bzero(pcrSelect, PCR_SELECT_MAX);
	*sizeofSelect = PCR_SELECT_MIN;

	policy_pcr = efi_freebsd_getenv_helper("KernGeomEliPassphraseFromTpm2PolicyPcr");
	if (policy_pcr == NULL)
		return TPM_ALG_ERROR;

	setenv("kern.geom.eli.passphrase.from_tpm2.policy_pcr", policy_pcr, 1);

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
			alg = resolve_hash_alg_name(p);
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

	return alg;
}


static void pause(time_t secs) {
	time_t now;
	time_t then = getsecs();
	do {
		now = getsecs();
	} while (now - then < secs);
}


static EFI_STATUS tpm2_parse_efivar_nvindex_spec(TPMI_RH_NV_INDEX *out) {
	char *freeme = efi_freebsd_getenv_helper("KernGeomEliPassphraseFromTpm2NvIndex");
	if (freeme == NULL)
		return EFI_NOT_FOUND;
	setenv("kern.geom.eli.passphrase.from_tpm2.nvindex", freeme, 1);
	*out = strtol(freeme, NULL, 16);
	(void)free(freeme);
	return EFI_SUCCESS;
}


void tpm2_check_efivars() {
	pcr_selection.hash = tpm2_parse_efivar_policy_spec(pcr_selection.pcrSelect, &pcr_selection.sizeofSelect);
	if (pcr_selection.hash == TPM_ALG_ERROR) {
		printf("Failed to retrieve TPM2 passphrase config (policy), will not try to retrieve.\n");
		return;
	}
	if (tpm2_parse_efivar_nvindex_spec(&nvindex) != EFI_SUCCESS) {
		printf("Failed to retrieve TPM2 passphrase config (nvindex), will not try to retrieve.\n");
		return;
	}
	try_retrieve_passphrase_from_tpm = 1;
}


static void zero_env_var(const char *name) {
	struct env_var *ev = env_getenv(name);
	if (ev != NULL) {
		char *zerome = ev->ev_value;
		while (*zerome) {
			*zerome++ = '\0';
		}
	}
}


void destroy_crypto_info() {
	explicit_bzero(&passphrase_from_nvindex, sizeof(passphrase_from_nvindex));
	zero_env_var("kern.geom.eli.passphrase");
	zero_env_var("kern.geom.eli.passphrase.from_tpm2.passphrase");
	struct keybuf *freeme = (struct keybuf*) malloc(sizeof(struct keybuf) + sizeof(struct keybuf_ent) * GELI_MAX_KEYS);
	freeme->kb_nents = GELI_MAX_KEYS;
	for (unsigned int i = 0; i < GELI_MAX_KEYS; i++) {
		freeme->kb_ents[i].ke_type = KEYBUF_TYPE_GELI;
		explicit_bzero(&freeme->kb_ents[i].ke_data[0], MAX_KEY_BYTES);
	}
	geli_import_key_buffer(freeme);
	(void)free(freeme);
}


static void pause_and_exit(EFI_STATUS status) {
	destroy_crypto_info();
	pause(TPM2_PAUSE_BEFORE_EXIT);
	efi_exit(status);
}


static EFI_STATUS tpm2_start_policy_session(TPMI_SH_AUTH_SESSION *SessionHandle) {
	EFI_STATUS status;

	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPM2B_NONCE NonceTPM;
	status = Tpm2StartAuthSession (
	    TPM_RH_NULL,	// TpmKey
	    TPM_RH_NULL,	// Bind
	    &NonceCaller,
	    &Salt,
	    TPM_SE_POLICY,	// SessionType
	    &Symmetric,
	    TPM_ALG_SHA256,	//AuthHash
	    SessionHandle,
	    &NonceTPM
	);
	if (status != EFI_SUCCESS) {
		printf("Tpm2StartAuthSession() failed - 0x%lx.\n", status);
		return status;
	}

	TPM2B_DIGEST PcrDigest = { .size = 0 };
	TPML_PCR_SELECTION Pcrs = {
	    .count = 1,
	    .pcrSelections = {
	        pcr_selection
	    }
	};
	status = Tpm2PolicyPCR(
	    *SessionHandle, 	// PolicySession
	    &PcrDigest,
	    &Pcrs
	);
	if (status != EFI_SUCCESS) {
		printf("Tpm2PolicyPCR() failed - 0x%lx.\n", status);
		return status;
	}

	return EFI_SUCCESS;
}


void tpm2_retrieve_passphrase() {
	if (!try_retrieve_passphrase_from_tpm)
		return;

	printf("Trying to retrieve passphrase from TPM...\n");

	EFI_STATUS status;

	TPMI_SH_AUTH_SESSION SessionHandle;
	status = tpm2_start_policy_session(&SessionHandle);
	if (status != EFI_SUCCESS) {
		printf("tpm2_start_policy_session() failed - 0x%lx.\n", status);
		return;
	}

	TPM2B_NV_PUBLIC nvpublic;
	TPM2B_NAME nvname;
	status = Tpm2NvReadPublic (nvindex, &nvpublic, &nvname);
	if (status != EFI_SUCCESS) {
		printf("Tpm2NvReadPublic() failed - 0x%lx.\n", status);
		return;
	}
	if (nvpublic.nvPublic.dataSize >= MAX_DIGEST_BUFFER) {
		printf("Stored passphrase too long.\n");
		return;
	}

	TPMS_AUTH_COMMAND AuthSession = {
	    .sessionHandle = SessionHandle,
	    .nonce = { 0 },
	    .sessionAttributes = 0,
	    .hmac = { 0 }
	};
	status = Tpm2NvRead(nvindex, nvindex, &AuthSession, nvpublic.nvPublic.dataSize, 0, &passphrase_from_nvindex);
	if (status != EFI_SUCCESS) {
		printf("Tpm2NvRead() failed - 0x%lx.\n", status);
		return;
	}
	passphrase_from_nvindex.buffer[nvpublic.size] = '\0';
	setenv("kern.geom.eli.passphrase", passphrase_from_nvindex.buffer, 1);
	passphrase_was_retrieved = 1;
	setenv("kern.geom.eli.passphrase.from_tpm2.was_retrieved", "1", 1);

	status = tpm2_start_policy_session(&SessionHandle);
	if (status != EFI_SUCCESS) {
		printf("tpm2_start_policy_session() failed - 0x%lx.\n", status);
		return;
	}

	AuthSession.sessionHandle = SessionHandle;
	status = Tpm2NvReadLock(nvindex, nvindex, &AuthSession);
	if (status != EFI_SUCCESS) {
		printf("Tpm2NvReadLock() failed - 0x%lx.\n", status);
		pause_and_exit(EFI_DEVICE_ERROR);
	}
}


static void tpm2_sha256(const char *data, size_t n, char *digest) {
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, n);
	SHA256_Final(digest, &ctx);
}


static void sha256_digest_make_human_readable(const unsigned char *digest, char *digest_human_readable) {
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(digest_human_readable + i * 2, 3, "%02x", digest[i]);
	}
	digest_human_readable[2 * SHA256_DIGEST_LENGTH] = '\0';
}


void tpm2_check_passphrase_marker() {
	int fd;
	struct stat st;
	BYTE buf[SHA256_DIGEST_LENGTH * 2 + 1];
	const int timeout = TPM2_PAUSE_BEFORE_EXIT;
	SHA256_CTX ctx;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char digest_human_readable[SHA256_DIGEST_LENGTH * 2 + 1];
	char *salt;

	if (!passphrase_was_retrieved) {
		printf("Passphrase from TPM was not used - OK.\n");
		return;
	}

	if ((fd = open("/.passphrase_marker", O_RDONLY)) < 0) {
		printf("Selected rootfs does not contain the passphrase marker, rebooting in %d secs...\n", timeout);
		goto exit_timeout;
	}

	if (fstat(fd, &st) < 0) {
		printf("fstat() on passphrase marker failed, rebooting in %d secs...\n", timeout);
		close(fd);
		goto exit_timeout;
	}

	if (st.st_uid != 0 || (st.st_mode & 0077)) {
		printf("Passphrase marker has wrong permissions set, rebooting in %d secs...\n", timeout);
		close(fd);
		goto exit_timeout;
	}

	if (st.st_size > SHA256_DIGEST_LENGTH * 2) {
		printf("Passphrase marker too long, rebooting in %d secs...\n", timeout);
		close(fd);
		goto exit_timeout;
	}

	if (read(fd, buf, st.st_size) != st.st_size) {
		printf("Failed to read the passphrase marker, rebooting in %d secs...\n", timeout);
		close(fd);
		goto exit_timeout;
	}
	buf[st.st_size] = '\0';
	close(fd);

	SHA256_Init(&ctx);
	salt = efi_freebsd_getenv_helper("KernGeomEliPassphraseFromTpm2Salt");
	if (salt != NULL) {
		SHA256_Update(&ctx, salt, strlen(salt));
		setenv("kern.geom.eli.passphrase.from_tpm2.salt", salt, 1);
	}
	SHA256_Update(&ctx, passphrase_from_nvindex.buffer, passphrase_from_nvindex.size);
	SHA256_Final(digest, &ctx);
	sha256_digest_make_human_readable(digest, digest_human_readable);

	if (strncmp(buf, digest_human_readable, SHA256_DIGEST_LENGTH * 2 + 1) != 0) {
		printf("Passphrase marker does not match, rebooting in %d secs...\n", timeout);
		goto exit_timeout;
	}

	printf("Passphrase marker found and matching - autoboot in %d secs...\n", TPM2_AUTOBOOT_TIMEOUT);
	setenv("kern.geom.eli.passphrase.from_tpm2.passphrase", passphrase_from_nvindex.buffer, 1);
	setenv("autoboot_delay", "-1", 1);
	setenv("beastie_disable", "YES", 1);
	pause(TPM2_AUTOBOOT_TIMEOUT);
	return;

exit_timeout:
	pause_and_exit(EFI_NOT_FOUND);
}


static int tpm2_parse_efivar_pcrextend_spec(TPMI_ALG_HASH *hashAlg, BYTE *digest) {
    char *pcrExtend_freeme = efi_freebsd_getenv_helper("KernGeomEliPassphraseFromTpm2PcrExtend");
    if (pcrExtend_freeme == NULL) {
        return -1;
    }

    char *p;
    int pcrNum = strtol(pcrExtend_freeme, &p, 10);
    if (errno != 0) {
        printf("Could not parse PCR number in KernGeomEliPassphraseFromTpm2PcrExtend.\n");
        pause_and_exit(EFI_INVALID_PARAMETER);
    }
    if (*p != ':') {
        printf("Expected colon in KernGeomEliPassphraseFromTpm2PcrExtend.\n");
        pause_and_exit(EFI_INVALID_PARAMETER);
    }
    p++;
    const char *hashAlgName = p;
    while (*p != '\0' && *p != '=') {
        p++;
    }
    if (*p != '=') {
        printf("Expected equal sign in KernGeomEliPassphraseFromTpm2PcrExtend.\n");
        pause_and_exit(EFI_INVALID_PARAMETER);
    }
    *p = '\0';
    *hashAlg = resolve_hash_alg_name(hashAlgName);
    p++;
    // BYTE digest[sizeof(TPMU_HA)];
    int index = 0;
    while (*p != '\0') {
        if (*(p + 1) == '\0') {
            printf("Specified digest has odd length in KernGeomEliPassphraseFromTpm2PcrExtend.\n");
            pause_and_exit(EFI_INVALID_PARAMETER);
        }
        if (index >= sizeof(TPMU_HA)) {
            printf("Specified digest is too long in KernGeomEliPassphraseFromTpm2PcrExtend.\n");
            pause_and_exit(EFI_INVALID_PARAMETER);
        }
        char buf[] = { *p, *(p + 1), '\0' };
        digest[index++] = strtol(buf, NULL, 16);
        if (errno != 0) {
            printf("Could not parse digest in KernGeomEliPassphraseFromTpm2PcrExtend.\n");
            pause_and_exit(EFI_INVALID_PARAMETER);
        }
        p += 2;
    }

    (void)free(pcrExtend_freeme);
    return pcrNum;
}


void tpm2_pcr_extend() {
    TPMI_DH_PCR         PcrHandle = 8;
    TPML_DIGEST_VALUES  Digests = {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM_ALG_SHA256,
                .digest = {
                    .sha256 = {
                        0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d,
                        0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d,
                        0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d,
                        0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d, 0xfb, 0x5d
                    }
                }
            }
        }
    };
    EFI_STATUS status;

    status = Tpm2LocateProtocol();
    if (EFI_ERROR(status)) {
        printf("No TPM2.0? No need to extend PCR...\n");
        return;
    }

    status = Tpm2PcrExtend (PcrHandle, &Digests);

    if (status != EFI_SUCCESS) {
        printf("Tpm2PcrExtend() failed.\n");
        pause_and_exit(status);
    }

    printf("Tpm2PcrExtend() OK.\n");
}
