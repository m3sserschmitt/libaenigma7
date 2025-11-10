#ifndef PRIVATE_KEY_HH
#define PRIVATE_KEY_HH

#include "AsymmetricKey.hh"

class PrivateKey : public AsymmetricKey
{
private:
    PrivateKey(const PrivateKey &);
    const PrivateKey &operator=(const PrivateKey &);

protected:
    virtual void setKeyFromBio(void *bio, char *passphrase) override;

    virtual void setKeyFromFile(FILE *file, char *passphrase) override;

public:
    virtual ~PrivateKey() {}

    PrivateKey() : AsymmetricKey() {}
};

#endif
