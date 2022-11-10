#include <efi.h>

#include <IndustryStandard/Tpm20.h>

#include "gkut2tcg.h"

#pragma pack(1)

typedef struct {
    TPM2_COMMAND_HEADER    Header;
    TPMI_DH_PCR            PcrHandle;
    UINT32                 AuthorizationSize;
    TPMS_AUTH_COMMAND      AuthSessionPcr;
    TPML_DIGEST_VALUES     DigestValues;
} TPM2_PCR_EXTEND_COMMAND;

typedef struct {
    TPM2_RESPONSE_HEADER    Header;
    UINT32                  ParameterSize;
    TPMS_AUTH_RESPONSE      AuthSessionPcr;
} TPM2_PCR_EXTEND_RESPONSE;

#pragma pack()


typedef struct {
  TPMI_ALG_HASH    HashAlgo;
  UINT16           HashSize;
  UINT32           HashMask;
} INTERNAL_HASH_INFO;


static INTERNAL_HASH_INFO  mHashInfo[] = {
  { TPM_ALG_SHA1,    SHA1_DIGEST_SIZE,    HASH_ALG_SHA1    },
  { TPM_ALG_SHA256,  SHA256_DIGEST_SIZE,  HASH_ALG_SHA256  },
  { TPM_ALG_SM3_256, SM3_256_DIGEST_SIZE, HASH_ALG_SM3_256 },
  { TPM_ALG_SHA384,  SHA384_DIGEST_SIZE,  HASH_ALG_SHA384  },
  { TPM_ALG_SHA512,  SHA512_DIGEST_SIZE,  HASH_ALG_SHA512  },
};


static UINT16 EFIAPI GetHashSizeFromAlgo (IN TPMI_ALG_HASH  HashAlgo) {
  UINTN  Index;

  for (Index = 0; Index < sizeof (mHashInfo)/sizeof (mHashInfo[0]); Index++) {
    if (mHashInfo[Index].HashAlgo == HashAlgo) {
      return mHashInfo[Index].HashSize;
    }
  }

  return 0;
}


EFI_STATUS Tpm2PcrExtend (
    TPMI_DH_PCR         PcrHandle,
    TPML_DIGEST_VALUES  *Digests
) {
    EFI_STATUS                Status;
    TPM2_PCR_EXTEND_COMMAND   Cmd;
    TPM2_PCR_EXTEND_RESPONSE  Res;
    UINT32                    CmdSize;
    UINT32                    RespSize;
    UINT32                    ResultBufSize;
    UINT8                     *Buffer;
    UINTN                     Index;
    UINT32                    SessionInfoSize;
    UINT16                    DigestSize;

    Cmd.Header.tag         = SwapBytes16 (TPM_ST_SESSIONS);
    Cmd.Header.commandCode = SwapBytes32 (TPM_CC_PCR_Extend);
    Cmd.PcrHandle          = SwapBytes32 (PcrHandle);


    //
    // Add in Auth session
    //
    Buffer = (UINT8 *)&Cmd.AuthSessionPcr;

    // sessionInfoSize
    SessionInfoSize       = CopyAuthSessionCommand (NULL, Buffer);
    Buffer               += SessionInfoSize;
    Cmd.AuthorizationSize = SwapBytes32 (SessionInfoSize);

    // Digest Count
    WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32 (Digests->count));
    Buffer += sizeof (UINT32);

    // Digest
    for (Index = 0; Index < Digests->count; Index++) {
        WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (Digests->digests[Index].hashAlg));
        Buffer    += sizeof (UINT16);
        DigestSize = GetHashSizeFromAlgo (Digests->digests[Index].hashAlg);
        if (DigestSize == 0) {
            printf("Unknown hash algorithm %d\r\n", Digests->digests[Index].hashAlg);
            return EFI_DEVICE_ERROR;
        }

        memcpy(Buffer,
            &Digests->digests[Index].digest,
            DigestSize);
        Buffer += DigestSize;
    }

    CmdSize              = (UINT32)((UINTN)Buffer - (UINTN)&Cmd);
    Cmd.Header.paramSize = SwapBytes32 (CmdSize);

    ResultBufSize = sizeof (Res);
    Status        = Tpm2SubmitCommand (CmdSize, (UINT8 *)&Cmd, &ResultBufSize, (UINT8 *)&Res);
    if (EFI_ERROR (Status)) {
        return Status;
    }

    if (ResultBufSize > sizeof (Res)) {
        printf("Tpm2PcrExtend: Failed ExecuteCommand: Buffer Too Small\r\n");
        return EFI_BUFFER_TOO_SMALL;
    }


    //
    // Validate response headers
    //
    RespSize = SwapBytes32 (Res.Header.paramSize);
    if (RespSize > sizeof (Res)) {
        printf("Tpm2PcrExtend: Response size too large! %d\r\n", RespSize);
        return EFI_BUFFER_TOO_SMALL;
    }

    //
    // Fail if command failed
    //
    if (SwapBytes32 (Res.Header.responseCode) != TPM_RC_SUCCESS) {
        printf("Tpm2PcrExtend: Response Code error! 0x%08x\r\n", SwapBytes32 (Res.Header.responseCode));
        return EFI_DEVICE_ERROR;
    }

    //
    // Unmarshal the response
    //

    // None

    return EFI_SUCCESS;
}
