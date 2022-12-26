#include "../../include/cryptography/AsymmetricKey.hh"
#include "../../include/cryptography/AsymmetricCipher.hh"
#include <openssl/bio.h>
#include <string>
#include <openssl/pem.h>

bool AsymmetricKey::setKeyData(ConstBytes keyData, Size len, Plaintext passphrase)
{
    this->freeKey();

    BIO *bio = BIO_new_mem_buf((ConstBase64)keyData, len);

    if (not bio)
    {
        return false;
    }

    switch (this->getKeyType())
    {
    case PublicKey:
        this->setPkey(PEM_read_bio_PUBKEY(bio, nullptr, this->getKeyPassphraseCallback(), passphrase));
        break;
    case PrivateKey:
        this->setPkey(PEM_read_bio_PrivateKey(bio, nullptr, this->getKeyPassphraseCallback(), passphrase));
        break;
    default:
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);

    return this->notNullPkey();
}

bool AsymmetricKey::readKeyFile(ConstPlaintext path, Plaintext passphrase)
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
        this->setPkey(PEM_read_PUBKEY(keyFile, nullptr, this->getKeyPassphraseCallback(), passphrase));
        break;
    case PrivateKey:
        this->setPkey(PEM_read_PrivateKey(keyFile, nullptr, this->getKeyPassphraseCallback(), passphrase));
        break;
    default:
        return false;
    }

    return this->notNullPkey();
}
