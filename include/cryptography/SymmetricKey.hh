#ifndef SYMMETRIC_KEY_HH
#define SYMMETRIC_KEY_HH

#include "Key.hh"
#include "Constants.hh"
#include <cstring>

class SymmetricKey : public Key
{
private:
    unsigned char *key;

    bool writeKeyData(const unsigned char *keyData)
    {
        if (keyData and this->key)
        {
            memcpy(this->key, keyData, SYMMETRIC_KEY_SIZE);
            return true;
        }

        return false;
    }

    void zeroKeyData()
    {
        if (this->notNullKeyData())
        {
            memset(this->key, 0, SYMMETRIC_KEY_SIZE);
        }
    }

    void cleanup() { this->freeKey(); }

public:
    SymmetricKey(const SymmetricKey &) = delete;

    const SymmetricKey &operator=(const SymmetricKey &) = delete;

    ~SymmetricKey() override { this->cleanup(); }

    SymmetricKey() : Key() { this->key = new unsigned char[SYMMETRIC_KEY_SIZE]; }

    explicit SymmetricKey(const unsigned char *keyData) : Key()
    {
        this->key = new unsigned char[SYMMETRIC_KEY_SIZE];
        this->writeKeyData(keyData);
    }

    bool setKeyData(const unsigned char *keyData, unsigned int keyLen, const char *passphrase) override { return this->writeKeyData(keyData); }

    bool readKeyFile(const char *path, const char *passphrase) override { return false; }

    [[nodiscard]] const void *getKeyData() const override { return this->key; }

    [[nodiscard]] int getSize() const override { return this->notNullKeyData() ? SYMMETRIC_KEY_SIZE : -1; }

    void freeKey() override
    {
        this->zeroKeyData();
        delete[] this->key;
        this->key = nullptr;
    }
};

#endif
