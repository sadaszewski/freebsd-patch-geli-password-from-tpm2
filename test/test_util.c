#include "gkut2util.h"

#include <stdio.h>
#include <assert.h>

void test_01_bin2hex() {
    printf("====== test_01_bin2hex() ======\n");
    UINT8 bin[] = { 0xde, 0xea, 0xdb, 0xee, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0xde, 0xea, 0xdb, 0xee, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0xde, 0xea, 0xdb, 0xee, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    UINT8 hex[1024];
    EFI_STATUS status;

    printf("sizeof(bin): %d\n", sizeof(bin));
    status = gkut2_bin2hex(bin, sizeof(bin), &hex[0]);
    assert(status == EFI_SUCCESS);
    printf("hex: %s\n", hex);
    printf("Success!\n");
}

void test_02_hex2bin() {
    printf("====== test_02_hex2bin() ======\n");
    UINT8 hex[] = "deeadbeef0010203040506deeadbeef0010203040506deeadbeef0010203040506";
    UINT8 bin[1024];
    UINT64 bin_len;
    EFI_STATUS status;
    status = gkut2_hex2bin(&hex[0], &bin[0], &bin_len);
    assert(status == EFI_SUCCESS);
    printf("bin_len: %llu\n", bin_len);
    printf("bin: ");
    for (UINT64 i = 0; i < bin_len; i++) {
        printf("%02x ", bin[i]);
    }
    printf("\n");
    printf("Success!\n");
}

void test_03_hex2bin_bad_char() {
    printf("====== test_03_hex2bin_bad_char() ======\n");
    UINT8 hex[] = "deeadbeef0zz0203040506deeadbeef0010203040506deeadbeef0010203040506";
    UINT8 bin[1024];
    UINT64 bin_len;
    EFI_STATUS status;
    status = gkut2_hex2bin(&hex[0], &bin[0], &bin_len);
    assert(status == EFI_INVALID_PARAMETER);
    printf("bin_len: %llu\n", bin_len);
    printf("bin: ");
    for (UINT64 i = 0; i < bin_len; i++) {
        printf("%02x ", bin[i]);
    }
    printf("\n");
    printf("Success!\n");
}

void test_04_random_bytes() {
    printf("====== test_04_random_bytes() ======\n");
    UINT8 buf[1024];
    EFI_STATUS status;
    memset(&buf[0], 0, sizeof(buf));
    for (int i = 0; i < 1024; i++) {
        assert(buf[i] == 0);
    }
    status = gkut2_random_bytes(&buf[0], 1024);
    assert(status == EFI_SUCCESS);
    printf("buf: ");
    for (int i = 0; i < 64; i++) {
        printf("%02x ", buf[i]);
    }
    printf("... ");
    for (int i = 1024 - 64; i < 1024; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
    printf("Success!\n");
}

void mock_rng_init();

int main() {
    mock_rng_init();
    test_01_bin2hex();
    test_02_hex2bin();
    test_03_hex2bin_bad_char();
    test_04_random_bytes();
}
