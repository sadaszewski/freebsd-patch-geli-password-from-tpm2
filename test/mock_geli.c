#include "geliboot.h"

#include <stdio.h>

void geli_add_key(geli_ukey key) {
    printf("geli_add_key - mock implementation does nothing\n");
}

void geli_import_key_buffer(struct keybuf *keybuf) {
    printf("geli_import_key_buffer - mock implementation does nothing\n");
}
