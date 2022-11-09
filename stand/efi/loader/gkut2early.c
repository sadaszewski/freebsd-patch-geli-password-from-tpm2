#include "gkut2fs.h"
#include "gkut2dec.h"
#include "gkut2early.h"
#include "gkut2parse.h"

void gkut2_free_read_necessary_result(gkut2_read_necessary_result *res) {
    (void)free(res->iv);
    (void)free(res->sym_pub);
    (void)free(res->sym_priv);
    (void)free(res->passphrase_enc);
    (void)free(res->policy_pcr);
}

EFI_STATUS gkut2_read_necessary(gkut2_read_necessary_result *res) {
    EFI_STATUS Status;
    UINT8 *iv_freeme = NULL;
    UINT64 iv_size = 1024;
    UINT8 *sym_pub_freeme = NULL;
    UINT64 sym_pub_size = 1024;
    UINT8 *sym_priv_freeme = NULL;
    UINT64 sym_priv_size = 1024;
    UINT8 *passphrase_enc_freeme = NULL;
    UINT64 passphrase_enc_size = 1024;
    UINT8 *policy_pcr_freeme = NULL;
    UINT64 policy_pcr_size = 1024;

    Status = gkut2_efi_open_volume();
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_open_volume - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/iv", &iv_size, &iv_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_efi_read_file - iv - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/sym.pub", &sym_pub_size, &sym_pub_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_efi_read_file - sym.pub - %lu\n", Status);
        goto Error;
    }
    
    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/sym.priv", &sym_priv_size, &sym_priv_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_efi_read_file - sym.priv - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/passphrase.enc", &passphrase_enc_size, &passphrase_enc_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_efi_read_file - passphrase.enc - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_read_file(u"/efi/freebsd/gkut2/policy_pcr", &policy_pcr_size, &policy_pcr_freeme);
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_efi_efi_read_file - policy_pcr - %lu\n", Status);
        goto Error;
    }

    Status = gkut2_efi_close_volume();
    if (EFI_ERROR(Status)) {
        printf("gkut2_early - gkut2_close_volume - %lu\n", Status);
        goto Error;
    }

    res->iv = iv_freeme;
    res->sym_pub = sym_pub_freeme;
    res->sym_priv = sym_priv_freeme;
    res->passphrase_enc = passphrase_enc_freeme;
    res->policy_pcr = policy_pcr_freeme;
    res->iv_size = iv_size;
    res->sym_pub_size = sym_pub_size;
    res->sym_priv_size = sym_priv_size;
    res->passphrase_enc_size = passphrase_enc_size;
    res->policy_pcr_size = policy_pcr_size;

    return EFI_SUCCESS;

Error:
    (void)free(iv_freeme);
    (void)free(sym_pub_freeme);
    (void)free(sym_priv_freeme);
    (void)free(passphrase_enc_freeme);
    (void)free(policy_pcr_freeme);

    return Status;
}
