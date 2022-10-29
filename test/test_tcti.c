#include <tss2/tss2_common.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_swtpm.h>
#include <assert.h>
#include <stdio.h>
#include <malloc.h>

int main() {
    size_t tcti_size = 0;
    TSS2_RC ret;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    ret = Tss2_Tcti_Swtpm_Init(NULL, &tcti_size, NULL);
    assert(ret == TSS2_RC_SUCCESS);
    printf("tcti_size: %llu\n", tcti_size);

    ctx = malloc(tcti_size);
    assert(ctx != NULL);

    ret = Tss2_Tcti_Swtpm_Init(ctx, &tcti_size, "host=127.0.0.1,port=12345");
    assert(ret == TSS2_RC_SUCCESS);
}
