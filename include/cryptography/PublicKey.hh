#ifndef PUBLIC_KEY_HH
#define PUBLIC_KEY_HH

#include <fstream>
#include "AsymmetricKey.hh"

class PublicKey : public AsymmetricKey
{
private:
    PublicKey(const PublicKey &);
    const PublicKey &operator=(const PublicKey &);

protected:
    virtual void setKeyFromBio(void *bio, char *passphrase) override;

    virtual void setKeyFromFile(FILE *file, char *passphrase) override;

public:
    virtual ~PublicKey() {}
    PublicKey() : AsymmetricKey() {}
};

#endif
