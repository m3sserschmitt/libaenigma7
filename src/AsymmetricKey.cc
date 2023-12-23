#include "cryptography/AsymmetricKey.hh"

#include <openssl/bio.h>
#include <openssl/pem.h>

bool AsymmetricKey::setKeyData(const unsigned char *keyData, unsigned int len, char *passphrase)
{
    this->freeKey();

    BIO *bio = BIO_new_mem_buf((const char*)keyData, len);

    if (not bio)
    {
        return false;
    }

    switch (this->getKeyType())
    {
    case PublicKey:
        this->key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, passphrase);
        break;
    case PrivateKey:
        this->key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, passphrase);
        break;
    default:
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);

    return this->notNullKeyData();
}

bool AsymmetricKey::readKeyFile(const char *path, char *passphrase)
{
    this->freeKey();

    FILE *keyFile = fopen(path, "r");

    if (not keyFile)
    {
        return false;
    }

    switch (this->getKeyType())
    {
    case PublicKey:
        this->key = PEM_read_PUBKEY(keyFile, nullptr, nullptr, passphrase);
        break;
    case PrivateKey:
        this->key = PEM_read_PrivateKey(keyFile, nullptr, nullptr, passphrase);
        break;
    default:
        fclose(keyFile);
        return false;
    }

    fclose(keyFile);

    return this->notNullKeyData();
}
