#ifndef _GKUT2LATE_H_
#define _GKUT2LATE_H_

#include <efi.h>

#include <crypto/sha2/sha256.h>

void gkut2_sha256(const char *data, size_t n, char *digest);

EFI_STATUS gkut2_check_rootfs_marker(GKUT2B_SALT *salt, GKUT2B_GELI_KEY *geli_key);

EFI_STATUS gkut2_pcr_extend();

#endif
