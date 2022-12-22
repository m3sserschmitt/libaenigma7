#ifndef ASYMMETRIC_KEY_HH
#define ASYMMETRIC_KEY_HH

#include "Key.hh"
#include <string>

class AsymmetricKey : public Key
{
    typedef struct bio_st BIO;
    typedef struct rsa_st RSA;
    typedef struct evp_pkey_st EVP_PKEY;
    typedef RSA *(*pemReadBioPtr)(BIO *);

    static BIO *getBIO(const char *PEM);
    static RSA *getPubkeyRSA(BIO *bio);
    static RSA *getPrivkeyRSA(BIO *bio);
    static EVP_PKEY *getEvpPkey(const char *PEM, pemReadBioPtr ptr);

public:
    const EncrypterResult *lock(const EncrypterData *) override;

    const EncrypterResult *unlock(const EncrypterData *) override;
};

#endif
