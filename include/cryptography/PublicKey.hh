#ifndef PUBLIC_KEY_HH
#define PUBLIC_KEY_HH

#include <fstream>
#include "AsymmetricKey.hh"

class PublicKey : public AsymmetricKey
{
protected:
    void setKeyFromBio(void *bio, char *passphrase) override;

    void setKeyFromFile(FILE *file, char *passphrase) override;

public:
    PublicKey() : AsymmetricKey() {}
    PublicKey(const PublicKey &) = delete;
    const PublicKey &operator=(const PublicKey &) = delete;
};

#endif
