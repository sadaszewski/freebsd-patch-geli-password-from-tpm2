#include "gkut2fs.h"
#include "gkut2early.h"

#include <stdio.h>
#include <assert.h>

void mock_simplefs_init();

void test_01_gkut2_early() {
    printf("======= test_01_gkut2early() ========\n");
    gkut2_early_result res;
    EFI_STATUS Status = gkut2_early(&res);
    assert(Status == EFI_SUCCESS);
    printf("Sizes: %llu, %llu, %llu, %llu, %llu\n",
        res.iv_size, res.sym_pub_size, res.sym_priv_size, res.passphrase_enc_size, res.policy_pcr_size);
    gkut2_free_early_result(&res);
    printf("Success!\n");
}

int main() {
    mock_simplefs_init();
    test_01_gkut2_early();
}

