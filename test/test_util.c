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
    assert(status == EFI_BUFFER_TOO_SMALL);
    printf("bin_len: %llu\n", bin_len);
    printf("bin: ");
    for (UINT64 i = 0; i < bin_len; i++) {
        printf("%02x ", bin[i]);
    }
    printf("\n");
    printf("Success!\n");
}

int main() {
    test_01_bin2hex();
    test_02_hex2bin();
    test_03_hex2bin_bad_char();
}
