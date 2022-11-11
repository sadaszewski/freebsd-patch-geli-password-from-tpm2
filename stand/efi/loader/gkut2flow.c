#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include "gkut2early.h"
#include "gkut2late.h"
#include "gkut2flow.h"
#include "gkut2b64.h"

#include "geliboot.h"

#include <time.h>

#include <stdlib.h>

#define TPM2_PAUSE_BEFORE_EXIT 10
#define NONCE_SIZE 64


static void pause_and_exit(EFI_STATUS status);


static void gkut2_set_env_vars(GKUT2_READ_NECESSARY_RESULT *res, GKUT2B_GELI_KEY *geli_key) {
    UINT8 nonce[NONCE_SIZE];
    UINT8 nonce_b64[NONCE_SIZE * 2 + 1];
    UINT64 nonce_b64_size;
    UINT8 buffer[sizeof(res->salt.buffer) + sizeof(geli_key->buffer)];
    UINT8 digest[SHA256_DIGEST_SIZE];
    UINT8 buffer2[SHA256_DIGEST_SIZE + NONCE_SIZE];
    UINT8 digest_b64[SHA256_DIGEST_SIZE * 2 + 1];
    UINT64 digest_b64_len;

    srandom(time(NULL));
    for (int i = 0; i < NONCE_SIZE; i++) {
        nonce[i] = random();
    }
    gkut2_base64_encode(&nonce[0], NONCE_SIZE, &nonce_b64[0], &nonce_b64_size);
    nonce_b64[nonce_b64_size] = 0;

    memcpy(&buffer[0], &res->salt.buffer[0], res->salt.size);
    memcpy(&buffer[res->salt.size], &geli_key->buffer[0], geli_key->size);
    gkut2_sha256(&buffer[0], res->salt.size + geli_key->size, &digest[0]);
    explicit_bzero(&buffer[0], sizeof(buffer));

    memcpy(&buffer2[0], &digest[0], SHA256_DIGEST_SIZE);
    memcpy(&buffer2[SHA256_DIGEST_SIZE], &nonce[0], NONCE_SIZE);
    gkut2_sha256(&buffer2[0], SHA256_DIGEST_SIZE + NONCE_SIZE, &digest[0]);
    explicit_bzero(&buffer2[0], sizeof(buffer2));

    gkut2_base64_encode(&digest[0], SHA256_DIGEST_SIZE, &digest_b64[0], &digest_b64_len);
    digest_b64[digest_b64_len] = 0;

    setenv("kern.geom.eli.kut2.nonce", nonce_b64, 1);
    setenv("kern.geom.eli.kut2.digest", digest_b64, 1);
    setenv("autoboot_delay", "-1", 1);
    setenv("beastie_disable", "YES", 1);
}


EFI_STATUS gkut2_early(GKUT2_STATE *state) {
    GKUT2_READ_NECESSARY_RESULT res;
    EFI_STATUS status;

    status = gkut2_read_necessary(&res);
    if (EFI_ERROR(status)) {
        printf("gkut2_early - gkut2_read_necessary - %lu\n", status);
        return status;
    }

    GKUT2B_GELI_KEY geli_key;
    UINT64 size = sizeof(geli_key.buffer);
    status = gkut2_decrypt_key(&res, &geli_key.buffer[0], &size);
    geli_key.size = size;
    if (EFI_ERROR(status)) {
        printf("gkut2_early - gkut2_decrypt_key - %lu\n", status);
        goto Error;
    }

    state->KeyWasDecrypted = 1;

    status = gkut2_check_passphrase_marker(&res.salt, &geli_key);
    if (EFI_ERROR(status)) {
        printf("gkut2_early - gkut2_check_passphrase_marker - %lu\n", status);
        goto Error;
    }

    gkut2_set_env_vars(&res, &geli_key);

    geli_add_key(&geli_key.buffer[0]);
    explicit_bzero(&geli_key.buffer[0], geli_key.size);

    return EFI_SUCCESS;

Error:
    explicit_bzero(&geli_key.buffer[0], geli_key.size);

    return status;
}


void gkut2_late(GKUT2_STATE *state) {
    EFI_STATUS status;

    status = gkut2_pcr_extend();
    if (EFI_ERROR(status)) {
        printf("gkut2_late - gkut2_pcr_extend - %lu\n", status);
        if (state->KeyWasDecrypted) {
            pause_and_exit(status);
        }
    }
}


static void gkut2_pause(time_t secs) {
	time_t now;
	time_t then = getsecs();
	do {
		now = getsecs();
	} while (now - then < secs);
}


void gkut2_destroy_crypto_info() {
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
	gkut2_destroy_crypto_info();
	gkut2_pause(TPM2_PAUSE_BEFORE_EXIT);
	efi_exit(status);
}
