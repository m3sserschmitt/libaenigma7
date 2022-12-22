#include "../../include/cryptography/AsymmetricKey.hh"
#include <openssl/bio.h>
#include <string>
#include <openssl/pem.h>

BIO *AsymmetricKey::getBIO(const char *PEM)
{
    return BIO_new_mem_buf(PEM, -1);
}

RSA *AsymmetricKey::getPubkeyRSA(BIO *bio)
{
    return PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
}

RSA *AsymmetricKey::getPrivkeyRSA(BIO *bio)
{
    return PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
}

EVP_PKEY *AsymmetricKey::getEvpPkey(const char *PEM, pemReadBioPtr ptr)
{
    BIO *bio = getBIO(PEM);

    if (not bio)
    {
        return nullptr;
    }

    RSA *rsa = ptr(bio);

    if (not rsa)
    {
        BIO_free(bio);

        return nullptr;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();

    if (not pkey)
    {
        BIO_free(bio);
        RSA_free(rsa);

        return nullptr;
    }

    if (not EVP_PKEY_assign_RSA(pkey, rsa))
    {
        BIO_free(bio);
        RSA_free(rsa);

        return nullptr;
    }

    return pkey;
}

const EncrypterResult *AsymmetricKey::lock(const EncrypterData *)
{
}

const EncrypterResult *AsymmetricKey::unlock(const EncrypterData *)
{
}