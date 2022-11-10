ALL=test_encrypt_decrypt test_context_load test_simplefs \
    test_ext_public test_early

CFLAGS+=-I../stand/efi/include -I../stand/efi/loader -I. -ggdb

all: $(ALL)

clean:
	rm -v $(ALL)

test_encrypt_decrypt: test_encrypt_decrypt.c \
	../stand/efi/loader/gkut2dec.c \
	../stand/efi/loader/gkut2tcg.c \
    ../stand/efi/loader/gkut2auth.c \
    mock_tpm2_api.c \
    mock_tpm2_impl.c \
    mock_simplefs.c \
    mock_bs.c
	gcc $(CFLAGS) test_encrypt_decrypt.c \
		../stand/efi/loader/gkut2dec.c \
        ../stand/efi/loader/gkut2tcg.c \
        ../stand/efi/loader/gkut2auth.c \
        mock_tpm2_api.c \
        mock_tpm2_impl.c \
        mock_simplefs.c \
        mock_bs.c \
        -o test_encrypt_decrypt \
        -ltss2-tcti-swtpm

test_simplefs: test_simplefs.c \
    mock_simplefs.c \
    ../stand/efi/loader/gkut2fs.c \
    mock_bs.c
	gcc $(CFLAGS) test_simplefs.c \
        mock_simplefs.c \
        ../stand/efi/loader/gkut2fs.c \
        mock_bs.c \
        -o test_simplefs

test_ext_public: test_ext_public.c \
	../stand/efi/loader/gkut2dec.c \
	../stand/efi/loader/gkut2tcg.c \
    ../stand/efi/loader/gkut2auth.c \
    mock_tpm2_api.c \
    mock_tpm2_impl.c \
    mock_bs.c
	gcc $(CFLAGS) test_ext_public.c \
		../stand/efi/loader/gkut2dec.c \
        ../stand/efi/loader/gkut2tcg.c \
        ../stand/efi/loader/gkut2auth.c \
        mock_tpm2_api.c \
        mock_tpm2_impl.c \
        mock_bs.c \
        -o test_ext_public \
        -ltss2-tcti-swtpm

test_early: test_early.c \
    ../stand/efi/loader/gkut2early.c \
    ../stand/efi/loader/gkut2fs.c \
    ../stand/efi/loader/gkut2parse.c \
    ../stand/efi/loader/gkut2auth.c \
    ../stand/efi/loader/gkut2tcg.c \
    ../stand/efi/loader/gkut2dec.c \
    mock_bs.c \
    mock_simplefs.c \
    mock_tpm2_api.c \
    mock_tpm2_impl.c
	gcc $(CFLAGS) test_early.c \
        ../stand/efi/loader/gkut2early.c \
        ../stand/efi/loader/gkut2fs.c \
        ../stand/efi/loader/gkut2parse.c \
        ../stand/efi/loader/gkut2auth.c \
        ../stand/efi/loader/gkut2tcg.c \
        ../stand/efi/loader/gkut2dec.c \
        mock_bs.c \
        mock_simplefs.c \
        mock_tpm2_api.c \
	mock_tpm2_impl.c \
        -o test_early \
        -ltss2-tcti-swtpm

test_context_load: test_context_load.c
	gcc $(CFLAGS) test_context_load.c -o test_context_load

