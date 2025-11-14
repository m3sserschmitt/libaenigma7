#include "cryptography/PrivateKey.hh"
#include "cryptography/Constants.hh"
#include "cryptography/Aenigma.hh"

#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>

#ifndef __ANDROID__
#include "cryptography/KernelKeys.hh"

char PrivateKey::privateKeyMasterPassphraseName[MASTER_PASSPHRASE_MAX_NAME_SIZE + 1] = MASTER_PASSPHRASE_DEFAULT_NAME;

int PrivateKey::readMasterPassphraseCallback(char *buf, int size, int rwflag, void *u)
{
    int keyId = SearchKernelKey(privateKeyMasterPassphraseName, KERNEL_KEY_KEYRING);
    if (keyId < 0)
    {
        return -1;
    }
    return ReadKernelKey(keyId, buf);
}

bool PrivateKey::setMasterPassphraseName(const char *name, size_t len)
{
    if(len > MASTER_PASSPHRASE_MAX_NAME_SIZE)
    {
        return false;
    }
    strncpy(privateKeyMasterPassphraseName, name, len);
    privateKeyMasterPassphraseName[len] = 0;
    return true;
}

int PrivateKey::createMasterPassphrase(const char *passphrase, size_t len)
{
    return CreateKernelKey(passphrase, len, privateKeyMasterPassphraseName, KERNEL_KEY_KEYRING);
}

void PrivateKey::setKeyFromBio(void *bio, char *passphrase)
{
    this->setKey(PEM_read_bio_PrivateKey((BIO *)bio, nullptr, passphrase ? nullptr : readMasterPassphraseCallback, passphrase));
}

void PrivateKey::setKeyFromFile(FILE *file, char *passphrase)
{
    this->setKey(PEM_read_PrivateKey(file, nullptr, passphrase ? nullptr : readMasterPassphraseCallback, passphrase));
}

#else

void PrivateKey::setKeyFromBio(void *bio, char *passphrase)
{
    this->setKey(PEM_read_bio_PrivateKey((BIO *)bio, nullptr, nullptr, passphrase));
}

void PrivateKey::setKeyFromFile(FILE *file, char *passphrase)
{
    this->setKey(PEM_read_PrivateKey(file, nullptr, nullptr, passphrase));
}

#endif
