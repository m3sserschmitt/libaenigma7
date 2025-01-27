#include "cryptography/AsymmetricKey.hh"

#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>

static char *AllocatePassphraseBuffer(const char *passphrase)
{
    if (not passphrase)
    {
        return nullptr;
    }

    int size = strlen(passphrase);
    char *newBuffer = new char[size + 1];
    strncpy(newBuffer, passphrase, size);
    newBuffer[size] = 0;

    return newBuffer;
}

bool AsymmetricKey::setKeyData(const unsigned char *keyData, unsigned int len, const char *passphrase)
{
    this->freeKey();

    BIO *bio = BIO_new_mem_buf((const char *)keyData, len);

    if (not bio)
    {
        return false;
    }

    char *p = nullptr;

    switch (this->getKeyType())
    {
    case PublicKey:
        p = AllocatePassphraseBuffer(passphrase);
        this->key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, p);
        break;
    case PrivateKey:
        p = AllocatePassphraseBuffer(passphrase);
        this->key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, p);
        break;
    default:
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);
    delete[] p;

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

    char *p = nullptr;

    switch (this->getKeyType())
    {
    case PublicKey:
        p = AllocatePassphraseBuffer(passphrase);
        this->key = PEM_read_PUBKEY(keyFile, nullptr, nullptr, p);
        break;
    case PrivateKey:
        p = AllocatePassphraseBuffer(passphrase);
        this->key = PEM_read_PrivateKey(keyFile, nullptr, nullptr, p);
        break;
    default:
        fclose(keyFile);
        return false;
    }

    fclose(keyFile);
    delete[] p;

    return this->notNullKeyData();
}

void AsymmetricKey::freeKey()
{
    EVP_PKEY_free((EVP_PKEY *)this->key);
    this->key = nullptr;
}

int AsymmetricKey::getSize() const
{
    return this->notNullKeyData() ? EVP_PKEY_size((EVP_PKEY *)this->key) : -1;
}
