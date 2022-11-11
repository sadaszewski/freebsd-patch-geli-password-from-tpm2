from argparse import ArgumentParser
import os
import subprocess
import tempfile
from contextlib import ExitStack
import shutil


def create_parser():
    parser = ArgumentParser()
    parser.add_argument('--freebsd-src-dir', type=str, default='/usr/src')
    parser.add_argument('--vm-image', type=str, required=True)
    parser.add_argument('--vm-geli-passphrase', type=str, default='admin')
    parser.add_argument('--vm-bootenv', type=str, default='default')
    parser.add_argument('--md-unit', type=int, default=15)
    parser.add_argument('--zfs-partition-number', type=int, default=2)
    parser.add_argument('--efi-partition-number', type=int, default=1)
    parser.add_argument('--vm-pool-name', type=str, default='zroot')
    parser.add_argument('--alt-pool-name', type=str, default='altzroot')
    parser.add_argument('--alt-root', type=str, default='/tmp/altroot')
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as d, \
        ExitStack() as es:

        os.chmod(d, 0o700)

        print('mdconfig')
        subprocess.check_output([ 'mdconfig',
            '-u', str(args.md_unit),
            '-f', args.vm_image ])
        es.callback(lambda: print('mdconfig destroy') or \
            subprocess.check_output([ 'mdconfig', '-d', '-u', str(args.md_unit) ]))

        print('geli attach')
        with open(os.path.join(d, 'passfile'), 'w') as f:
            f.write(args.vm_geli_passphrase)
        subprocess.check_output([ 'geli', 'attach',
            '-j', os.path.join(d, 'passfile'),
            f'/dev/md{args.md_unit}p{args.zfs_partition_number}' ])
        es.callback(lambda: print('geli detach') or \
            subprocess.check_output([ 'geli', 'detach', f'/dev/md{args.md_unit}p{args.zfs_partition_number}.eli' ]))

        print('zpool import')
        os.makedirs(args.alt_root, exist_ok=True)
        subprocess.check_output([ 'zpool', 'import',
            '-f',
            '-N',
            '-R', args.alt_root,
            '-d', f'/dev/md{args.md_unit}p{args.zfs_partition_number}.eli',
            args.vm_pool_name,
            args.alt_pool_name, '-t' ])
        es.callback(lambda: print('zpool export') or \
            subprocess.check_output([ 'zpool', 'export', args.alt_pool_name ]))

        print('mount bootenv')
        subprocess.check_output([ 'mount',
            '-t', 'zfs',
            f'{args.alt_pool_name}/ROOT/{args.vm_bootenv}',
            args.alt_root ])
        es.callback(lambda: print('umount bootenv') or \
            subprocess.check_output([ 'umount', args.alt_root ]))

        print('mount EFI partition')
        os.makedirs(os.path.join(args.alt_root, 'boot', 'efi'), exist_ok=True)
        subprocess.check_output([ 'mount',
            '-t', 'msdosfs',
            f'/dev/md{args.md_unit}p{args.efi_partition_number}',
            os.path.join(args.alt_root, 'boot', 'efi') ])
        es.callback(lambda: print('umount EFI partition') or \
            subprocess.check_output([ 'umount', os.path.join(args.alt_root, 'boot', 'efi') ]))

        print('install')
        env = dict(os.environ)
        env['DESTDIR'] = args.alt_root
        # os.makedirs(os.path.join(d, 'stand_destdir', 'usr', 'share', 'man', 'man8'))
        # os.makedirs(os.path.join(d, 'stand_destdir', 'usr', 'share', 'man', 'man5'))
        subprocess.run([ 'make', 'install' ],
            cwd=os.path.join(args.freebsd_src_dir, 'stand'),
            env=env, check=True)

        print('copy setup_gkut2.py script...')
        shutil.copyfile('setup_gkut2.py',
            os.path.join(args.alt_root, 'usr', 'sbin', 'setup_gkut2.py'))

        print('copy to EFI partition')
        os.makedirs(os.path.join(args.alt_root, 'boot', 'efi', 'efi', 'boot'), exist_ok=True)
        os.makedirs(os.path.join(args.alt_root, 'boot', 'efi', 'efi', 'freebsd'), exist_ok=True)
        # shutil.copyfile(os.path.join(args.alt_root, 'boot', 'loader_lua.efi'),
        #     os.path.join(args.alt_root, 'boot', 'efi', 'efi', 'boot', 'bootx64.efi'))
        shutil.copyfile(os.path.join(args.alt_root, 'boot', 'loader_lua.efi'),
            os.path.join(args.alt_root, 'boot', 'efi', 'efi', 'freebsd', 'loader.efi'))


if __name__ == '__main__':
    main()
