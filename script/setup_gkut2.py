#!/usr/bin/env python

import subprocess
import os
import random
import tempfile
import hashlib
import base64
import shutil
from argparse import ArgumentParser


def create_parser():
    parser = ArgumentParser()
    parser.add_argument('--efi-target-dir', type=str, default='/boot/efi/efi/freebsd/gkut2')
    parser.add_argument('--geom', type=str)
    parser.add_argument('--nbits', type=int, default=256)
    parser.add_argument('--pcr-policy', type=str, default='sha256:0,2,4,7,8')
    parser.add_argument('--marker-filename', type=str, default='/.passphrase_marker')
    parser.add_argument('--iv-nbits', type=int, default=128)
    parser.add_argument('--no-geli', action='store_true')
    parser.add_argument('--geli-key-nbits', type=int, default=512)
    return parser


def detect_geom():
    geom = [ ln for ln in \
        subprocess.check_output([ 'geli', 'list' ]).decode('utf-8').strip().split('\n') \
            if 'Geom name:' in ln ][0]
    geom = geom.split()[-1][:-len('.eli')]
    return geom


def main():
    parser = create_parser()
    args = parser.parse_args()

    os.makedirs(args.efi_target_dir, exist_ok=True)

    geom = args.geom or detect_geom()
    print('ELI geom:', geom)

    print('Generating GELI key...')
    newkey = random.getrandbits(args.geli_key_nbits).to_bytes(args.geli_key_nbits // 8, 'little')

    print('Generating salt, TPM2 owner password, primary key auth value...')
    newsalt, newownerpass, symauthvalue = [ random.getrandbits(args.nbits).to_bytes(args.nbits // 8, 'little') \
        for _ in range(3) ]

    print('Generating IV...')
    iv = random.getrandbits(args.iv_nbits).to_bytes(args.iv_nbits // 8, 'little')

    with open(os.path.join(args.efi_target_dir, 'salt'), 'wb') as f:
        f.write(newsalt)

    with open(os.path.join(args.efi_target_dir, 'iv'), 'wb') as f:
        f.write(iv)

    with open(os.path.join(args.efi_target_dir, 'policy_pcr'), 'w') as f:
        f.write(args.pcr_policy)

    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o700)

        for fnam, data in { '.newkey': newkey, '.newownerpass': newownerpass,
            '.symauthvalue': symauthvalue }.items():
            with open(os.path.join(d, fnam), 'wb') as f:
                f.write(data)

        print('Clearing TPM2...')
        subprocess.check_output([ 'tpm2_clear' ])

        print('Taking ownership of TPM2...')
        for hier in [ 'owner', 'endorsement', 'lockout' ]:
            subprocess.check_output([ 'tpm2_changeauth',
                '-c', hier, 'file:' + os.path.join(d, '.newownerpass') ])

        print('Generating passphrase marker...')
        sha256 = hashlib.sha256()
        sha256.update(newsalt)
        sha256.update(newkey)
        new_passphrase_marker = sha256.digest()
        with open(args.marker_filename, 'wb') as f:
            f.write(new_passphrase_marker)
        os.chmod(args.marker_filename, 0o600)

        print('Reading PCRs...')
        subprocess.check_output([ 'tpm2_pcrread',
            args.pcr_policy,
            '-o', os.path.join(d, '.pcrvalues') ])

        print('Adjusting PCRs...')
        st = os.stat(os.path.join(d, '.pcrvalues'))
        subprocess.check_output([ 'truncate',
            '-s', str(st.st_size - 32),
            os.path.join(d, '.pcrvalues') ])

        subprocess.check_output([ 'truncate',
            '-s', str(st.st_size),
            os.path.join(d, '.pcrvalues') ])

        print('Generating policy digest...')
        subprocess.check_output([ 'tpm2_createpolicy',
            '-L', os.path.join(d, '.policydigest'),
            '--policy-pcr',
            '-l', args.pcr_policy,
            '-f', os.path.join(d, '.pcrvalues') ])

        print('Creating primary key...')
        subprocess.check_output([ 'tpm2_createprimary',
            '-c', os.path.join(d, '.primarycontext'),
            '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt',
            '-P', 'file:' + os.path.join(d, '.newownerpass') ])

        print('Persisting primary key...')
        subprocess.check_output([ 'tpm2_evictcontrol', 
            '-c', '0x80000000',
            '-P', 'file:' + os.path.join(d, '.newownerpass') ])

        print('Write primary handle...')
        with open(os.path.join(args.efi_target_dir, 'primary_handle'), 'w') as f:
            f.write('0x%08X' % (0x81000000))

        print('Creating symmetric key...')
        subprocess.check_output([ 'tpm2_create',
            '-C', '0x81000000',
            '-G', 'aes128cfb',
            '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign',
            '-u', os.path.join(args.efi_target_dir, 'sym.pub'),
            '-r', os.path.join(args.efi_target_dir, 'sym.priv'),
            '-p', 'file:' + os.path.join(d, '.symauthvalue'),
            '-L', os.path.join(d, '.policydigest'),
            '-c', os.path.join(d, '.symcontext') ]) 

        print('Encrypting GELI key...')
        subprocess.check_output([ 'tpm2_encryptdecrypt',
            '-c', os.path.join(d, '.symcontext'),
            '-p', 'file:' + os.path.join(d, '.symauthvalue'),
            '-t', os.path.join(args.efi_target_dir, 'iv'),
            '-o', os.path.join(args.efi_target_dir, 'geli_key.enc'),
            os.path.join(d, '.newkey') ])

        with open(os.path.join(d, '.newkey'), 'ab') as f:
            f.seek(0)
            f.write(b'\x00' * len(newkey))

        if not args.no_geli:
            print('Modifying GELI passphrase...')
            for i in range(2):
                subprocess.check_output([ 'geli', 'setkey',
                    '-n', str(i),
                    '-J', os.path.join(d, '.newpass'),
                    geom ])

    print('Success!')


if __name__ == '__main__':
    main()
