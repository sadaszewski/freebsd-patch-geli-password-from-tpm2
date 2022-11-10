#ifndef _DUMMY_SHA256_H_
#define _DUMMY_SHA256_H_

#include <efi.h>

#define SHA256_DIGEST_LENGTH 32

typedef struct {
} SHA256_CTX;

int SHA256_Init(SHA256_CTX*);
int SHA256_Update(SHA256_CTX*, const UINT8*, UINT64);
int SHA256_Final(UINT8*, SHA256_CTX*);

#endif
