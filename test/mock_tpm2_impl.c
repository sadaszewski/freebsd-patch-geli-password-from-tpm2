#include <tss2/tss2_common.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_swtpm.h>
#include <assert.h>
#include <stdio.h>
#include <malloc.h>

static TSS2_TCTI_CONTEXT *TctiContext;

int mock_submit_command(uint32_t InSize, uint8_t *InData, uint32_t OutSize, uint8_t *OutData) {
    printf("mock_submit_command()\n");
    TSS2_RC res = Tss2_Tcti_Transmit(TctiContext, InSize, InData);
    if (res != 0) {
        return 1;
    }
    size_t OutSize_sz = OutSize;
    printf("OutSize_sz: %lld\n", OutSize_sz);
    res = Tss2_Tcti_Receive(TctiContext, &OutSize_sz, OutData, -1);
    if (res != 0) {
        return 2;
    }
    return 0;
}

void mock_tpm2_init() {
    size_t tcti_size = 0;
    TSS2_RC ret;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    ret = Tss2_Tcti_Swtpm_Init(NULL, &tcti_size, NULL);
    assert(ret == TSS2_RC_SUCCESS);
    printf("tcti_size: %llu\n", tcti_size);

    printf("mockup_tpm2_init() :: sizeof(TPMS_CONTEXT): %lld\n", sizeof(TPMS_CONTEXT));
    printf("MAX_CONTEXT_SIZE: %d\n", TPM2_MAX_CONTEXT_SIZE);

    ctx = malloc(tcti_size);
    assert(ctx != NULL);

    ret = Tss2_Tcti_Swtpm_Init(ctx, &tcti_size, "host=127.0.0.1,port=12345");
    assert(ret == TSS2_RC_SUCCESS);

    TctiContext = ctx;
}

