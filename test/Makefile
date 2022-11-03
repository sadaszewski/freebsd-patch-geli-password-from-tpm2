ALL=test_encrypt_decrypt test_context_load

CFLAGS+=-I../stand/efi/include -I../stand/efi/loader -I.

all: $(ALL)

clean:
	rm -v $(ALL)

test_encrypt_decrypt: test_encrypt_decrypt.c \
	../stand/efi/loader/gkut2dec.c \
	../stand/efi/loader/gkut2tcg.c
	gcc $(CFLAGS) test_encrypt_decrypt.c \
		../stand/efi/loader/gkut2dec.c \
        ../stand/efi/loader/gkut2tcg.c \
        -o test_encrypt_decrypt

test_context_load: test_context_load.c
	gcc $(CFLAGS) test_context_load.c -o test_context_load

