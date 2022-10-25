from argparse import ArgumentParser
import os
import shutil


def create_parser():
    parser = ArgumentParser()
    parser.add_argument('--target-dir', type=str, default='/usr/src')
    return parser


def patch_stand_makefile(args):
    fname = os.path.join(args.target_dir, 'stand', 'efi', 'loader', 'Makefile')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines)):
        if lines[i].startswith('SRCS='):
            break
    else:
        raise RuntimeError('Could not find SRCS= line in stand/efi/loader/Makefile')

    for i in range(i + 1, len(lines)):
        if '\\' not in lines[i]:
            break
    else:
        raise RuntimeError('Could not find last line of SRCS= in stand/efi/loader/Makefile')

    lines = lines[:i+1] + [
        '',
        '.if ${MK_LOADER_TPM2_PASSPHRASE} == "yes"',
        'SRCS += tpm2.c',
        'SRCS += tpm2nv.c',
        'CFLAGS += -DLOADER_TPM2_PASSPHRASE',
        '.endif',
    ] + lines[i+1:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def patch_stand_main(args):
    fname = os.path.join(args.target_dir, 'stand', 'efi', 'loader', 'main.c')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith('#include'):
            break
    else:
        raise RuntimeError('Could not find last #include in stand/efi/loader/main.c')

    lines = lines[:i+1] + [
        '',
        '#ifdef LOADER_TPM2_PASSPHRASE',
        '#include "efitpm2.h"',
        '#include "efitpm2nv.h"',
        '#endif',
    ] + lines[i+1:]

    for i in range(i+1, len(lines)):
        if lines[i].strip().startswith('bcache_init'):
            break
    else:
        raise RuntimeError('Could not find bcache_init() call in stand/efi/loader/main.c')

    lines = lines[:i+1] + [
        '',
        '#ifdef LOADER_TPM2_PASSPHRASE',
        '\ttpm2_check_efivars();',
        '\ttpm2_retrieve_passphrase();',
        '\ttpm2_pcr_extend();',
        '#endif',
    ] + lines[i+1:]

    for i in range(i+1, len(lines)):
        if lines[i].strip().startswith('if (find_currdev('):
            break
    else:
        raise RuntimeError('Could not find find_currdev() call in stand/efi/loader/main.c')

    for i in range(i, len(lines)):
        if ';' in lines[i]:
            break
    else:
        raise RuntimeError('Could not find the end of the if-statement around the find_currdev() call in stand/efi/loader/main.c')

    lines = lines[:i+1] + [
        '',
        '#ifdef LOADER_TPM2_PASSPHRASE',
        '\ttpm2_check_passphrase_marker();',
        '#endif',
    ] + lines[i+1:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def patch_stand_interp(args):
    fname = os.path.join(args.target_dir, 'stand', 'common', 'interp.c')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith('#include'):
            break
    else:
        raise RuntimeError('Could not find last #include in stand/common/interp.c')

    lines = lines[:i+1] + [
        '',
        '#if defined(EFI) && defined(LOADER_TPM2_PASSPHRASE)',
        'void destroy_crypto_info(void); // ../efi/loader/tpm2.c',
        '#endif',
    ] + lines[i+1:]

    for i in range(i+1, len(lines)):
        if lines[i].strip().startswith('autoboot_maybe();'):
            break
    else:
        raise RuntimeError('Could not find autoboot_maybe() call in stand/common/interp.c')

    lines = lines[:i+1] + [
        '',
        '#if defined(EFI) && defined(LOADER_TPM2_PASSPHRASE)',
        '\tif (getenv("kern.geom.eli.passphrase.from_tpm2.was_retrieved")[0] == \'1\') {',
        '\t\t// we cannot allow any interaction',
        '\t\tdestroy_crypto_info();',
		'\t\texit(-1);',
        '\t}',
        '#endif',
    ] + lines[i+1:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def patch_src_opts_mk(args):
    fname = os.path.join(args.target_dir, 'share', 'mk', 'src.opts.mk')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines)):
        if lines[i].startswith('__DEFAULT_YES_OPTIONS'):
            break
    else:
        raise RuntimeError('Could not find __DEFAULT_YES_OPTIONS in share/mk/src.opts.mk')

    for i in range(i, len(lines)):
        if '\\' not in lines[i]:
            break
    else:
        raise RuntimeError('Could not find last line of __DEFAULT_YES_OPTIONS assignment in share/mk/src.opts.mk')

    lines[i] += ' \\'

    lines = lines[:i+1] + [
        '    LOADER_TPM2_PASSPHRASE'
    ] + lines[i+1:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def patch_generic_conf_amd64(args):
    fname = os.path.join(args.target_dir, 'sys', 'amd64', 'conf', 'GENERIC')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines)):
        if lines[i].startswith('options'):
            break
    else:
        raise RuntimeError('Could not find first options statements in sys/amd64/conf/GENERIC')

    lines = lines[:i] + [
        'options        LOADER_TPM2_PASSPHRASE         # TPM2 Passphrase Support (rootfs check)'
    ] + lines[i:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def patch_sys_conf_files(args):
    fname = os.path.join(args.target_dir, 'sys', 'conf', 'files')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines)):
        if lines[i].strip().startswith('kern/init_main.c'):
            break
    else:
        raise RuntimeError('Could not find kern/init_main.c in sys/conf/files')

    lines = lines[:i+1] + [
        'kern/tpm2cpm.c                  optional tpm2_passphrase'
    ] + lines[i+1:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def patch_sys_conf_options(args):
    fname = os.path.join(args.target_dir, 'sys', 'conf', 'options')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines)):
        if lines[i].strip().startswith('TPM_HARVEST'):
            break
    else:
        raise RuntimeError('Could not find TPM_HARVEST in sys/conf/options')

    lines = lines[:i+1] + [
        '',
        '# TPM2 Passphrase security',
        'TPM2_PASSPHRASE opt_tpm.h'
    ] + lines[i+1:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def main():
    parser = create_parser()
    args = parser.parse_args()
    marker_fname = os.path.join(args.target_dir, '.freebsd-patch-geli-password-from-tpm2-applied')
    if os.path.exists(marker_fname):
        raise RuntimeError('Patch already applied')

    shutil.copytree('stand', os.path.join(args.target_dir, 'stand'), dirs_exist_ok=True)
    patch_stand_makefile(args)
    patch_stand_main(args)
    patch_stand_interp(args)

    shutil.copytree('sys', os.path.join(args.target_dir, 'sys'), dirs_exist_ok=True)
    patch_src_opts_mk(args)
    patch_generic_conf_amd64(args)
    patch_sys_conf_files(args)
    patch_sys_conf_options(args)

    with open(marker_fname, 'w') as f:
        pass

  
if __name__ == '__main__':
    main()
  
