#ifndef PRIVATE_KEY_HH
#define PRIVATE_KEY_HH

#include "AsymmetricKey.hh"

class PrivateKey : public AsymmetricKey
{
private:
#ifndef __ANDROID__
    static char privateKeyMasterPassphraseName[];

    static int readMasterPassphraseCallback(char *buf, int size, int rwflag, void *u);
#endif
protected:
    void setKeyFromBio(void *bio, char *passphrase) override;

    void setKeyFromFile(FILE *file, char *passphrase) override;

public:
    PrivateKey() : AsymmetricKey() {}
    PrivateKey(const PrivateKey &) = delete;
    const PrivateKey &operator=(const PrivateKey &) = delete;
#ifndef __ANDROID__
    static bool setMasterPassphraseName(const char *name, size_t len);
    static int createMasterPassphrase(const char *passphrase, size_t len);
#endif
};

#endif
