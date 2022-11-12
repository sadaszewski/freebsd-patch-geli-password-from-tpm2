#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include "gkut2early.h"
#include "gkut2late.h"
#include "gkut2flow.h"
#include "gkut2util.h"

#include "geliboot.h"

#include <time.h>

#include <stdlib.h>

#define TPM2_PAUSE_BEFORE_EXIT 10
#define NONCE_SIZE 64


static void pause_and_exit(EFI_STATUS status);


static EFI_STATUS gkut2_set_env_vars(GKUT2B_SALT *salt, GKUT2B_GELI_KEY *geli_key) {
    UINT8 nonce[NONCE_SIZE];
    UINT8 nonce_hex[NONCE_SIZE * 2 + 1];
    UINT8 buffer[sizeof(salt->buffer) + sizeof(geli_key->buffer)];
    UINT8 digest[SHA256_DIGEST_SIZE];
    UINT8 buffer2[SHA256_DIGEST_SIZE + NONCE_SIZE];
    UINT8 digest_hex[SHA256_DIGEST_SIZE * 2 + 1];

    gkut2_random_bytes(&nonce[0], NONCE_SIZE);
    gkut2_bin2hex(&nonce[0], NONCE_SIZE, &nonce_hex[0]);

    memcpy(&buffer[0], &salt->buffer[0], salt->size);
    memcpy(&buffer[salt->size], &geli_key->buffer[0], geli_key->size);
    gkut2_sha256(&buffer[0], salt->size + geli_key->size, &digest[0]);
    explicit_bzero(&buffer[0], sizeof(buffer));

    memcpy(&buffer2[0], &digest[0], SHA256_DIGEST_SIZE);
    memcpy(&buffer2[SHA256_DIGEST_SIZE], &nonce[0], NONCE_SIZE);
    gkut2_sha256(&buffer2[0], SHA256_DIGEST_SIZE + NONCE_SIZE, &digest[0]);
    explicit_bzero(&buffer2[0], sizeof(buffer2));

    gkut2_bin2hex(&digest[0], SHA256_DIGEST_SIZE, &digest_hex[0]);

    setenv("kern.geom.eli.kut2.nonce", nonce_hex, 1);
    setenv("kern.geom.eli.kut2.digest", digest_hex, 1);
    setenv("autoboot_delay", "-1", 1);
    setenv("beastie_disable", "YES", 1);

    return EFI_SUCCESS;
}


EFI_STATUS gkut2_early(GKUT2_STATE *state) {
    GKUT2_READ_NECESSARY_RESULT res;
    EFI_STATUS status;

    status = gkut2_read_necessary(&res);
    if (EFI_ERROR(status)) {
        printf("gkut2_early - gkut2_read_necessary - %lu\n", status);
        return status;
    }

    UINT64 size = sizeof(state->geli_key.buffer);
    status = gkut2_decrypt_key(&res, &state->geli_key.buffer[0], &size);
    state->geli_key.size = size;
    if (EFI_ERROR(status)) {
        printf("gkut2_early - gkut2_decrypt_key - %lu\n", status);
        goto Error;
    }

    state->KeyWasDecrypted = 1;

    memcpy(&state->salt.buffer[0], &res.salt.buffer[0], res.salt.size);
    state->salt.size = res.salt.size;

    geli_add_key(&state->geli_key.buffer[0]);

    return EFI_SUCCESS;

Error:
    explicit_bzero(&state->geli_key.buffer[0], sizeof(state->geli_key.buffer));

    return status;
}


void gkut2_late(GKUT2_STATE *state) {
    EFI_STATUS status;

    if (state->KeyWasDecrypted) {
        status = gkut2_check_passphrase_marker(&state->salt, &state->geli_key);
        if (EFI_ERROR(status)) {
            printf("gkut2_late - gkut2_check_passphrase_marker - %lu\n", status);
            goto Error;
        }

        status = gkut2_set_env_vars(&state->salt, &state->geli_key);
        if (EFI_ERROR(status)) {
            printf("gkut2_late - gkut2_set_env_vars - %lu\n", status);
            goto Error;
        }

        explicit_bzero(&state->geli_key.buffer[0], sizeof(state->geli_key.buffer));
    }

    status = gkut2_pcr_extend();
    if (EFI_ERROR(status)) {
        printf("gkut2_late - gkut2_pcr_extend - %lu\n", status);
        if (state->KeyWasDecrypted) {
            pause_and_exit(status);
        }
    }

    return;

Error:
    explicit_bzero(&state->geli_key.buffer[0], sizeof(state->geli_key.buffer));
    pause_and_exit(status);
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
