#include <stdio.h>

#include "gkut2tcg.h"

void mock_tpm2_init();

int main() {
    printf("Hello world!\n");
    mock_tpm2_init();
    test_01_decrypt();
    BS->Exit(IH, EFI_INVALID_PARAMETER, 0, NULL);
}
