/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2021 Stanislaw R. Adaszewski
 * All rights reserved.
 *
 *	@(#)tpm2cpm.c	13.0 (Villeneuve) 11/27/21
 */


#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/syscallsubr.h>
#include <sys/proc.h>
#include <sys/kenv.h>

#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <sys/iov.h>
#include <crypto/sha2/sha256.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>
#include <geom/geom.h>
#include <geom/geom_int.h>
#include <geom/eli/g_eli.h>


extern bool dynamic_kenv;

static uint8_t g_nonce_buf[KENV_MVALLEN];
static uint64_t g_nonce_len;
static uint8_t g_digest_buf[KENV_MVALLEN];
static uint64_t g_digest_len;
static bool g_was_retrieved;


static void g_eli_zero_key(struct g_eli_softc *sc, struct g_eli_key *key) {
	mtx_assert(&sc->sc_ekeys_lock, MA_OWNED);
	explicit_bzero(&key->gek_key[0], sizeof(key->gek_key));
}


static void g_eli_my_key_destroy(struct g_eli_softc *sc) {
	mtx_lock(&sc->sc_ekeys_lock);
	if ((sc->sc_flags & G_ELI_FLAG_SINGLE_KEY) != 0) {
		explicit_bzero(sc->sc_ekey, sizeof(sc->sc_ekey));
	} else {
		struct g_eli_key *key;
		TAILQ_FOREACH(key, &sc->sc_ekeys_queue, gek_next) {
			g_eli_zero_key(sc, key);
		}
	}
	mtx_unlock(&sc->sc_ekeys_lock);
}


static void g_wipe_eli_keys_geom(struct g_geom *gp) {
	printf("Wiping ELI keys for geom: %s\n", gp->name);
	g_eli_my_key_destroy(gp->softc);
}


static void g_wipe_eli_keys_class(struct g_class *mp) {
	struct g_geom *gp;

	if (strcmp(mp->name, G_ELI_CLASS_NAME) != 0)
		return;

	LIST_FOREACH(gp, &mp->geom, geom)
	    g_wipe_eli_keys_geom(gp);
}


static void g_wipe_eli_keys(void *p, int flag) {
	struct g_class *mp;

	KASSERT(flag != EV_CANCEL, ("g_wipe_eli_keys was cancelled"));
	g_topology_assert();

	LIST_FOREACH(mp, &g_classes, class) {
		g_wipe_eli_keys_class(mp);
	}
}


static void wipe_geli_keys() {
	g_waitfor_event(g_wipe_eli_keys, NULL, M_WAITOK, NULL);
}


static void wipe_secrets() {
    explicit_bzero(&g_nonce_buf[0], KENV_MVALLEN + 1);
	explicit_bzero(&g_digest_buf[0], KENV_MVALLEN + 1);
}


static void static_kenv_wipe(const char *name) {
    if (dynamic_kenv) {
        panic("%s: called with dynamic kenv", __func__);
    }
	char *value = kern_getenv(name);
	if (value == NULL)
		return;
	while (*value) {
		*value++ = '\x01';
	}
}


static void wipe_kenv() {
	if (!dynamic_kenv) {
		static_kenv_wipe("kern.geom.eli.kut2.nonce");
		static_kenv_wipe("kern.geom.eli.kut2.digest");
	}
}


static void destroy_crypto_info() {
	wipe_kenv();
    wipe_secrets();
	wipe_geli_keys();
}


static int mypanic(const char *msg) {
	const int panic_reboot_wait_time = 10;
	int loop;

	printf("%s\n", msg);
	for (loop = panic_reboot_wait_time * 10; loop > 0; --loop) {
		DELAY(1000 * 100); /* 1/10th second */
	}
	destroy_crypto_info();
	panic("%s\n", msg);
}


static int hex2bin(const uint8_t *hex, uint8_t *bin, uint64_t *bin_len) {
    if (hex == NULL || bin == NULL || bin_len == NULL) {
        return (-1);
    }

    *bin_len = 0;
    while (*hex) {
        uint32_t val = 0;
        for (int i = 0; i < 2; i++) {
            uint8_t ch = hex[i];
            if (ch == 0) {
                return (-2);
            }
            if (ch >= 'a' && ch <= 'f') {
                ch = 10 + (ch - 'a');
            } else if (ch >= 'A' && ch <= 'F') {
                ch = 10 + (ch - 'A');
            } else if (ch >= '0' && ch <= '9') {
                ch = ch - '0';
            } else {
                return (-1);
            }
            val <<= 4;
            val |= ch;
        }
        *bin = val;
        bin++;
        hex += 2;
        *bin_len += 1;
    }

    return 0;
}


static void gkut2_check_passphrase_marker(void *param) {
	struct thread *td = curthread;

	int error;
	struct stat sb;
	int fd;
	struct iovec aiov;
	struct uio auio;
	char buf[SHA256_DIGEST_LENGTH];
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	if (!g_was_retrieved) {
		printf("GKUT2 - GELI Key from TPM2 was not used - OK.\n");
		return;
	}

	error = kern_statat(td, 0, AT_FDCWD, "/.passphrase_marker", UIO_SYSSPACE, &sb, NULL);
	if (error) {
		mypanic("kern_statat() on passphrase marker failed");
	}

	if (sb.st_uid != 0 || (sb.st_mode & 0077)) {
		mypanic("Passphrase marker has wrong permissions set");
	}

	if (sb.st_size > SHA256_DIGEST_LENGTH) {
		mypanic("Passphrase marker too long");
	}

	error = kern_openat(td, AT_FDCWD, "/.passphrase_marker", UIO_SYSSPACE, O_RDONLY, 0);
	if (error) {
		mypanic("Cannot open the passphrase marker");
	}
	fd = td->td_retval[0];

	aiov.iov_base = &buf[0];
	aiov.iov_len = sb.st_size;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = sb.st_size;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_readv(td, fd, &auio);
	if (error) {
		mypanic("Failed to read the passphrase marker");
	}
	buf[sb.st_size] = '\0';

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &buf[0], sb.st_size);
	SHA256_Update(&ctx, &g_nonce_buf[0], g_nonce_len);
	SHA256_Final(&digest[0], &ctx);

	if (memcmp(&digest[0], &g_digest_buf[0], SHA256_DIGEST_LENGTH) != 0) {
		mypanic("Passphrase marker does not match");
	}

	printf("Passphrase marker found and matching - we are done.\n");
    wipe_secrets();

	error = kern_close(td, fd);
	if (error) {
		printf("Failed to close passphrase marker - that's weird.\n");
	}
}


// This needs to happen before the dynamic kenv is initialized
static void gkut2_sanitize_kenv(void *param) {
    char *nonce = kern_getenv("kern.geom.eli.kut2.nonce");
    char *digest = kern_getenv("kern.geom.eli.kut2.digest");

    if (nonce == NULL && digest == NULL) {
        g_was_retrieved = false;
		return;
    } else {
        g_was_retrieved = true;
    }

    if (nonce == NULL) {
		mypanic("GKUT2 retrieved the key but kern.geom.eli.kut2.nonce is not set");
	}

	if (digest == NULL) {
		mypanic("GKUT2 retrieved the key but kern.geom.eli.kut2.digest is not set");
	}

	int status = hex2bin((uint8_t*) nonce, &g_nonce_buf[0], &g_nonce_len);
	if (status != 0) {
		printf("gkut2_sanitize_kenv - hex2bin - nonce - %d\n");
		mypanic("GKUT2 nonce could not be decoded");
	}

    if (hex2bin((uint8_t*) digest, &g_digest_buf[0], &g_digest_len) != 0) {
		mypanic("GKUT2 digest could not be decoded");
	}

	if (g_digest_len != SHA256_DIGEST_LENGTH) {
		mypanic("GKUT2 digest has wrong length");
	}

	freeenv(nonce); // this does nothing with static kenv
	freeenv(digest); // but hey let's keep up the good habits

	wipe_kenv();
}


SYSINIT(gkut2_sanitize_kenv, SI_SUB_KMEM, SI_ORDER_ANY, gkut2_sanitize_kenv, NULL);


static void gkut2cpm_init(void *param) {
	EVENTHANDLER_REGISTER(mountroot, gkut2_check_passphrase_marker, NULL, EVENTHANDLER_PRI_FIRST);
}


SYSINIT(gkut2cpm_init, SI_SUB_EVENTHANDLER + 1, SI_ORDER_ANY, gkut2cpm_init, NULL);
