#include "gkut2fs.h"
#include "gkut2early.h"

#include <stdio.h>
#include <assert.h>

void mock_simplefs_init();

void mock_tpm2_init();

void mock_tpm2_api_init();

void test_01_gkut2_read_necessary() {
    printf("======= test_01_gkut2_read_necessary() ========\n");
    GKUT2_READ_NECESSARY_RESULT res;
    EFI_STATUS Status = gkut2_read_necessary(&res);
    assert(Status == EFI_SUCCESS);
    printf("Sizes: %llu, %llu, %llu, %llu, %llu\n",
        res.iv.size, res.sym_pub.size, res.sym_priv.size, res.geli_key_enc.size, res.policy_pcr.size);
    printf("Primary handle: 0x%08X\n", res.primary_handle);
    printf("policy_pcr: %s\n", &res.policy_pcr.buffer[0]);
    printf("Success!\n");
}

void test_02_gkut2_decrypt_key() {
    EFI_STATUS Status;
    GKUT2_READ_NECESSARY_RESULT res;
    UINT64 key_size;
    UINT8 key[64];

    printf("====== test_02_gkut2_decrypt_key() ======\n");
    Status = gkut2_read_necessary(&res);
    assert(Status == EFI_SUCCESS);
    key_size = 64;
    Status = gkut2_decrypt_key(&res, &key[0], &key_size);
    assert(Status == EFI_SUCCESS);
    printf("Decrypted key: ");
    for (UINT64 i = 0; i < key_size; i++) {
        printf("%02X ", key[i]);
    }
    printf("\n");
    printf("Success!\n");
}

int main() {
    mock_simplefs_init();
    mock_tpm2_init();
    mock_tpm2_api_init();
    test_01_gkut2_read_necessary();
    test_02_gkut2_decrypt_key();
}
