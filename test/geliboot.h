#ifndef _DUMMY_GELIBOOT_H_
#define _DUMMY_GELIBOOT_H_

#include <efi.h>

#define G_ELI_USERKEYLEN 64

#define MAX_KEY_BITS	4096
#define	MAX_KEY_BYTES	(MAX_KEY_BITS / 8)

#define	GELI_MAX_KEYS			64

enum {
        KEYBUF_TYPE_NONE,
        KEYBUF_TYPE_GELI
};

typedef UINT8 geli_ukey[G_ELI_USERKEYLEN];

struct keybuf_ent {
        unsigned int ke_type;
        char ke_data[MAX_KEY_BYTES];
};

struct keybuf {
        unsigned int kb_nents;
        struct keybuf_ent kb_ents[];
};

void geli_add_key(geli_ukey key);
void geli_import_key_buffer(struct keybuf *keybuf);

#define SHA512_BLOCK_LENGTH		128
#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)

typedef struct SHA512Context {
	UINT64 state[8];
	UINT64 count[2];
	UINT8 buf[SHA512_BLOCK_LENGTH];
} SHA512_CTX;

struct hmac_ctx {
	SHA512_CTX	innerctx;
	SHA512_CTX	outerctx;
};

void g_eli_crypto_hmac_init(struct hmac_ctx *ctx, const UINT8 *hkey,
    UINTN hkeylen);
void g_eli_crypto_hmac_update(struct hmac_ctx *ctx, const UINT8 *data,
    UINTN datasize);
void g_eli_crypto_hmac_final(struct hmac_ctx *ctx, UINT8 *md, UINTN mdsize);

#endif
