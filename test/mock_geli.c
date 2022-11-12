#include "geliboot.h"

#include <stdio.h>

void geli_add_key(geli_ukey key) {
    printf("geli_add_key - mock implementation does nothing\n");
}

void geli_import_key_buffer(struct keybuf *keybuf) {
    printf("geli_import_key_buffer - mock implementation does nothing\n");
}

void g_eli_crypto_hmac_init(struct hmac_ctx *ctx, const UINT8 *hkey,
    UINTN hkeylen) {
    printf("g_eli_crypto_hmac_init - mock implementation does nothing\n");
}

void g_eli_crypto_hmac_update(struct hmac_ctx *ctx, const UINT8 *data,
    UINTN datasize) {
    printf("g_eli_crypto_hmac_update - mock implementation does nothing\n");
}

void g_eli_crypto_hmac_final(struct hmac_ctx *ctx, UINT8 *md, UINTN mdsize) {
    printf("g_eli_crypto_hmac_final - mock implementation does nothing\n");
}
