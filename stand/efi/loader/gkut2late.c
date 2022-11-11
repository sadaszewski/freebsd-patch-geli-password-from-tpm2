#include <efi.h>

#include <IndustryStandard/Tpm20.h>

#include "gkut2tcg.h"
#include "gkut2pcr.h"
#include "gkut2early.h"

#include <crypto/sha2/sha256.h>

#ifndef LOADER_GKUT2_PCRHANDLE
#define LOADER_GKUT2_PCRHANDLE 8
#endif


void gkut2_sha256(const char *data, size_t n, char *digest) {
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, n);
	SHA256_Final(digest, &ctx);
}


static void gkut2_sha256_hexdigest(const unsigned char *digest, char *digest_human_readable) {
	for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(digest_human_readable + i * 2, 3, "%02x", digest[i]);
	}
	digest_human_readable[2 * SHA256_DIGEST_LENGTH] = '\0';
}


EFI_STATUS gkut2_check_passphrase_marker(GKUT2B_SALT *salt, GKUT2B_GELI_KEY *geli_key) {
	int fd;
	struct stat st;
	BYTE buf[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	unsigned char digest[SHA256_DIGEST_LENGTH];

	if ((fd = open("/.passphrase_marker", O_RDONLY)) < 0) {
		printf("Selected rootfs does not contain the passphrase marker!\n");
		return EFI_NOT_FOUND;
	}

	if (fstat(fd, &st) < 0) {
		printf("fstat() on passphrase marker failed!\n");
		close(fd);
		return EFI_NOT_FOUND;
	}

	if (st.st_uid != 0 || (st.st_mode & 0077)) {
		printf("Passphrase marker has wrong permissions set!\n");
		close(fd);
		return EFI_INVALID_PARAMETER;
	}

	if (st.st_size > SHA256_DIGEST_LENGTH * 2) {
		printf("Passphrase marker too long!\n");
		close(fd);
		return EFI_BAD_BUFFER_SIZE;
	}

	if (read(fd, buf, st.st_size) != st.st_size) {
		printf("Failed to read the passphrase marker!\n");
		close(fd);
		return EFI_BAD_BUFFER_SIZE;
	}
	close(fd);

	SHA256_Init(&ctx);
    SHA256_Update(&ctx, &salt->buffer[0], salt->size);
	SHA256_Update(&ctx, &geli_key->buffer[0], geli_key->size);
	SHA256_Final(digest, &ctx);

	if (strncmp(buf, digest, SHA256_DIGEST_LENGTH) != 0) {
		printf("Passphrase marker does not match!\n");
		return EFI_INVALID_PARAMETER;
	}

	printf("Passphrase marker found and matching.\n");
	return EFI_SUCCESS;
}


EFI_STATUS gkut2_pcr_extend() {
    TPMI_DH_PCR         PcrHandle = LOADER_GKUT2_PCRHANDLE;
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
        printf("gkut2_pcr_extend - Tpm2LocateProtocol - No TPM2.0? - %lu\n", status);
        return status;
    }

    status = Tpm2PcrExtend (PcrHandle, &Digests);
    if (EFI_ERROR(status)) {
        printf("gkut2_pcr_extend - Tpm2PcrExtend - %lu\n", status);
        return status;
    }

    return EFI_SUCCESS;
}
