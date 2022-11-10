#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include "gkut2early.h"
#include "gkut2late.h"
#include "gkut2flow.h"

#include "geliboot.h"

#include <time.h>

#define TPM2_PAUSE_BEFORE_EXIT 10


static void pause_and_exit(EFI_STATUS status);


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

    if (state->KeyWasDecrypted) {
        setenv("kern.geom.eli.passphrase.from_tpm2.was_retrieved", "1", 1);
        setenv("autoboot_delay", "-1", 1);
        setenv("beastie_disable", "YES", 1);
    }
}


static void pause(time_t secs) {
	time_t now;
	time_t then = getsecs();
	do {
		now = getsecs();
	} while (now - then < secs);
}


static void destroy_crypto_info() {
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
