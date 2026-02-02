#include "cryptography/AsymmetricKey.hh"

#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>

char *AsymmetricKey::AllocatePassphraseBuffer(const char *passphrase, int &outSize)
{
    outSize = 0;
    if (not passphrase)
    {
        return nullptr;
    }

    outSize = (int)strlen(passphrase);
    char *newBuffer = new char[outSize + 1];
    strncpy(newBuffer, passphrase, outSize);
    newBuffer[outSize] = 0;

    return newBuffer;
}

bool AsymmetricKey::setKeyData(const unsigned char *keyData, unsigned int len, const char *passphrase)
{
    this->freeKey();

    BIO *bio = BIO_new_mem_buf((const char *)keyData, (int)len);

    if (not bio)
    {
        return false;
    }

    int pLen;
    char *p = AllocatePassphraseBuffer(passphrase, pLen);
    this->setKeyFromBio(bio, p);

    BIO_free(bio);
    if (p)
    {
        memset(p, 0, pLen);
        delete[] p;
    }

    return this->notNullKeyData();
}

bool AsymmetricKey::readKeyFile(const char *path, const char *passphrase)
{
    this->freeKey();

    FILE *keyFile = fopen(path, "r");

    if (not keyFile)
    {
        return false;
    }

    int pLen;
    char *p = AllocatePassphraseBuffer(passphrase, pLen);
    this->setKeyFromFile(keyFile, p);

    fclose(keyFile);
    if (p)
    {
        memset(p, 0, pLen);
        delete[] p;
    }
    return this->notNullKeyData();
}

void AsymmetricKey::freeKey()
{
    EVP_PKEY_free((EVP_PKEY *)this->getKeyData());
    this->setKey(nullptr);
}

int AsymmetricKey::getSize() const
{
    return this->notNullKeyData() ? EVP_PKEY_size((EVP_PKEY *)this->getKeyData()) : -1;
}
