#ifndef ASYMMETRIC_KEY_HH
#define ASYMMETRIC_KEY_HH

#include "Key.hh"
#include <fstream>

class AsymmetricKey : public Key
{
private:
    void *key;

    void cleanup() { this->freeKey(); }

protected:
    void setKey(void *keyData) { this->key = keyData; }

    static char *AllocatePassphraseBuffer(const char *passphrase, int &outSize);

    virtual void setKeyFromBio(void *bio, char *passphrase) = 0;

    virtual void setKeyFromFile(FILE *file, char *passphrase) = 0;

public:
    ~AsymmetricKey() override { this->cleanup(); }

    AsymmetricKey() : Key() { this->key = nullptr; }

    AsymmetricKey(const AsymmetricKey &) = delete;

    const AsymmetricKey &operator=(const AsymmetricKey &) = delete;

    bool setKeyData(const unsigned char *keyData, unsigned int len, const char *passphrase) override;

    bool readKeyFile(const char *path, const char *passphrase) override;

    [[nodiscard]] int getSize() const override;

    [[nodiscard]] const void *getKeyData() const override { return this->key; }

    void freeKey() override;
};

#endif
