#include <efi.h>
#include <efirng.h>

#include <stdlib.h>

EFI_STATUS
DummyGetInfo (
    IN struct _EFI_RNG_PROTOCOL		*This,
    IN  OUT UINTN			*RNGAlgorithmListSize,
    OUT EFI_RNG_ALGORITHM		*RNGAlgorithmList
    ) {

    printf("DummyGetInfo() does nothing\n");
    return EFI_UNSUPPORTED;
}

EFI_STATUS
DummyGetRNG (
    IN struct _EFI_RNG_PROTOCOL		*This,
    IN EFI_RNG_ALGORITHM		*RNGAlgorithm, OPTIONAL
    IN UINTN				RNGValueLength,
    OUT UINT8				*RNGValue
    ) {

    for (UINTN i = 0; i < RNGValueLength; i++) {
        RNGValue[i] = random();
    }

    return EFI_SUCCESS;
}

EFI_RNG_PROTOCOL DummyRngProtocol_ = {
    .GetInfo = DummyGetInfo,
    .GetRNG = DummyGetRNG
};

extern EFI_RNG_PROTOCOL *DummyRngProtocol;

void mock_rng_init() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    srandom(tv.tv_sec + tv.tv_usec);
    DummyRngProtocol = &DummyRngProtocol_;
}
