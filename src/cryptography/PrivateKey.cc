#include "cryptography/PrivateKey.hh"
#include "cryptography/Constants.hh"
#include "cryptography/Aenigma.hh"

#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>

#ifndef __ANDROID__
#include "cryptography/KernelKeys.hh"

char PrivateKey::masterPassphraseName[MASTER_PASSPHRASE_MAX_NAME_SIZE + 1] = MASTER_PASSPHRASE_DEFAULT_NAME;

int PrivateKey::masterPassphraseHandle = -1;

int PrivateKey::readMasterPassphraseCallback(char *buf, int size, int rwflag, void *u)
{
    return masterPassphraseHandle < 0 ? -1 : ReadKernelKey(masterPassphraseHandle, buf);
}

bool PrivateKey::setMasterPassphraseName(const char *name, size_t len)
{
    if (len > MASTER_PASSPHRASE_MAX_NAME_SIZE)
    {
        return false;
    }
    strncpy(masterPassphraseName, name, len);
    masterPassphraseName[len] = 0;
    return true;
}

int PrivateKey::createMasterPassphrase(const char *passphrase, size_t len)
{
    return (masterPassphraseHandle = CreateKernelKey(passphrase, len, masterPassphraseName, KERNEL_KEY_KEYRING));
}

bool PrivateKey::removeMasterPassphrase()
{
    auto result = RemoveKernelKey(masterPassphraseHandle);
    masterPassphraseHandle = -1;
    return result;
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
