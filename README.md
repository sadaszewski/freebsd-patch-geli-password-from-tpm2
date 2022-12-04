# freebsd-patch-geli-password-from-tpm2
A patch for the FreeBSD source tree which enables fetching of GELI password from TPM2 and booting a trusted root filesystem

```diff
- IMPORTANT NOTICE
-
- The patch now uses new approach based on standard TPM2 provisioning
- and decryption rather than storing the passphrase in an NV index.
- Additionally, GELI keys are now stored rather than the passphrase
- which eliminated the key computation phase, making things faster.
- Old code can be accessed in the "deprecated_using_nvindex" branch.
```
