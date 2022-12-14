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
        '.if ${MK_LOADER_GKUT2} == "yes"',
        'SRCS += gkut2auth.c',
        'SRCS += gkut2dec.c',
        'SRCS += gkut2early.c',
        'SRCS += gkut2flow.c',
        'SRCS += gkut2fs.c',
        'SRCS += gkut2late.c',
        'SRCS += gkut2parse.c',
        'SRCS += gkut2pcr.c',
        'SRCS += gkut2tcg.c',
        'SRCS += gkut2util.c',
        'SRCS += gkut2morc.c',
        'CFLAGS += -DLOADER_GKUT2',
        '.ifdef LOADER_GKUT2_PCRHANDLE',
        'CFLAGS += -DLOADER_GKUT2_PCRHANDLE=\\"${LOADER_GKUT2_PCRHANDLE}\\"',
        '.endif',
        '.ifdef LOADER_GKUT2_IGNORE_MORC_ERROR',
        'CFLAGS += -DLOADER_GKUT2_IGNORE_MORC_ERROR',
        '.endif',
        '.endif',
    ] + lines[i+1:]

    with open(fname, 'w') as f:
        f.write('\n'.join(lines))


def patch_stand_efi_main(args):
    fname = os.path.join(args.target_dir, 'stand', 'efi', 'loader', 'efi_main.c')

    with open(fname) as f:
        lines = f.read().split('\n')

    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip().startswith('BS->FreePages(heap'):
            break
    else:
        raise RuntimeError('Could not find BS->FreePages(heap, ...) in stand/efi/loader/efi_main.c')

    lines = lines[:i] + [
        '\texplicit_bzero((void*)(uintptr_t)heap, heapsize);'
    ] + lines[i:]

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
        '#ifdef LOADER_GKUT2',
        '#include "gkut2flow.h"',
        'GKUT2_STATE gkut2_state = {};',
        '#endif',
    ] + lines[i+1:]

    for i in range(i+1, len(lines)):
        if lines[i].strip().startswith('bcache_init'):
            break
    else:
        raise RuntimeError('Could not find bcache_init() call in stand/efi/loader/main.c')

    lines = lines[:i+1] + [
        '',
        '#ifdef LOADER_GKUT2',
        '\tgkut2_early(&gkut2_state);',
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
        '#ifdef LOADER_GKUT2',
        '\tgkut2_late(&gkut2_state);',
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
        '#if defined(EFI) && defined(LOADER_GKUT2)',
        '#include "gkut2flow.h"',
        'extern GKUT2_STATE gkut2_state; // ../efi/loader/main.c',
        '#endif',
    ] + lines[i+1:]

    for i in range(i+1, len(lines)):
        if lines[i].strip().startswith('autoboot_maybe();'):
            break
    else:
        raise RuntimeError('Could not find autoboot_maybe() call in stand/common/interp.c')

    lines = lines[:i+1] + [
        '',
        '#if defined(EFI) && defined(LOADER_GKUT2)',
        '\tif (gkut2_state.KeyWasDecrypted) {',
        '\t\t// we cannot allow any interaction',
        '\t\tgkut2_destroy_crypto_info();',
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
        '    LOADER_GKUT2'
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
        'options        GKUT2         # GELI Key Using TPM2 (GKUT2) Support (rootfs check)'
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
        'kern/gkut2cpm.c                  optional gkut2'
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
        'GKUT2 opt_gkut2.h'
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
    patch_stand_efi_main(args)
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
  
