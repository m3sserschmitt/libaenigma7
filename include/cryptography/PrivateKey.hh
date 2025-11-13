#ifndef PRIVATE_KEY_HH
#define PRIVATE_KEY_HH

#include "AsymmetricKey.hh"

class PrivateKey : public AsymmetricKey
{
protected:
    void setKeyFromBio(void *bio, char *passphrase) override;

    void setKeyFromFile(FILE *file, char *passphrase) override;

public:
    PrivateKey() : AsymmetricKey() {}
    PrivateKey(const PrivateKey &) = delete;
    const PrivateKey &operator=(const PrivateKey &) = delete;
};

#endif
