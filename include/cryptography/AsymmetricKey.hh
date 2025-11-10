#ifndef ASYMMETRIC_KEY_HH
#define ASYMMETRIC_KEY_HH

#include "Key.hh"
#include <fstream>

class AsymmetricKey : public Key
{
    void *key;

    AsymmetricKey(const AsymmetricKey &);

    const AsymmetricKey &operator=(const AsymmetricKey &);

protected:
    void *getKey() { return this->key; }

    void setKey(void *key) { this->key = key; }

    static char *AllocatePassphraseBuffer(const char *passphrase, int &outSize);

    virtual void setKeyFromBio(void *bio, char *passphrase) = 0;

    virtual void setKeyFromFile(FILE *file, char *passphrase) = 0;

public:
    ~AsymmetricKey() { this->freeKey(); }

    AsymmetricKey() : Key() { this->key = nullptr; }

    bool setKeyData(const unsigned char *keyData, unsigned int len, const char *passphrase = nullptr) override;

    bool readKeyFile(const char *path, const char *passphrase = nullptr) override;

    int getSize() const override;

    const void *getKeyData() const override { return this->key; }

    void freeKey() override;
};

#endif
