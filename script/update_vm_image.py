from argparse import ArgumentParser
import os
import subprocess
import tempfile
import shutil


def create_parser():
    parser = ArgumentParser()
    parser.add_argument('--freebsd-src-dir', type=str, default='/usr/src')
    parser.add_argument('--vm-image', type=str, required=True)
    parser.add_argument('--vm-geli-passphrase', type=str, default='admin')
    parser.add_argument('--vm-bootenv', type=str, default='default')
    parser.add_argument('--md-unit', type=int, default=15)
    parser.add_argument('--partition-number', type=int, default=2)
    parser.add_argument('--vm-pool-name', type=str, default='zroot')
    parser.add_argument('--alt-pool-name', type=str, default='altzroot')
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    print('mdconfig')
    subprocess.check_output([ 'mdconfig',
        '-u', str(args.md_unit),
        '-f', args.vm_image ])

    print('geli attach')
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o700)
        with open(os.path.join(d, 'passfile'), 'w') as f:
            f.write(args.vm_geli_passphrase)
        subprocess.check_output([ 'geli', 'attach',
            '-j', os.path.join(d, 'passfile'),
            f'/dev/md{args.md_unit}p{args.partition_number}' ])

    with tempfile.TemporaryDirectory() as d:
        print('install to destdir')
        env = dict(os.environ)
        env['DESTDIR'] = os.path.join(d, 'stand_destdir')
        os.makedirs(os.path.join(d, 'stand_destdir', 'usr', 'share', 'man', 'man8'))
        os.makedirs(os.path.join(d, 'stand_destdir', 'usr', 'share', 'man', 'man5'))
        subprocess.run([ 'make', 'install' ],
            cwd=os.path.join(args.freebsd_src_dir, 'stand'),
            env=env, check=True)

        os.makedirs(os.path.join(d, 'altroot'))

        print('zpool import')
        subprocess.check_output([ 'zpool', 'import',
            '-N',
            '-R', os.path.join(d, 'altroot'),
            '-d', f'/dev/md{args.md_unit}p{args.partition_number}.eli',
            args.vm_pool_name,
            args.alt_pool_name, '-t' ])

        print('mount bootenv')
        subprocess.check_output([ 'mount',
            '-t', 'zfs',
            f'{args.alt_pool_name}/ROOT/{args.vm_bootenv}',
            os.path.join(d, 'altroot') ])

        print('copy to bootenv')
        shutil.copytree(os.path.join(d, 'stand_destdir'),
            os.path.join(d, 'altroot'),
            dirs_exist_ok=True)

        print('zpool export')
        subprocess.check_output([ 'zpool', 'export', args.alt_pool_name ])

    print('geli detach')
    subprocess.check_output([ 'geli', 'detach', f'/dev/md{args.md_unit}p{args.partition_number}.eli' ])

    print('mdconfig destroy')
    subprocess.check_output([ 'mdconfig', '-d', '-u', str(args.md_unit) ])


if __name__ == '__main__':
    main()
