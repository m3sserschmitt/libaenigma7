#ifndef SYMMETRIC_KEY_HH
#define SYMMETRIC_KEY_HH

#include "RandomDataGenerator.hh"
#include "Constants.hh"
#include "Key.hh"

#include <openssl/evp.h>

class SymmetricKey : public Key
{
    Bytes keyData;

    SymmetricKey(const SymmetricKey &);
    const SymmetricKey &operator=(const SymmetricKey &);

    void setKeyData(Bytes keyData) { this->keyData = keyData; }

    Bytes getKeyData() { return this->keyData; }

    const Bytes getKeyData() const { return this->keyData; }

    bool writeKeyData(ConstBytes keyData)
    {
        Bytes localKeyData = this->getKeyData();

        if (keyData and localKeyData)
        {
            memcpy(localKeyData, keyData, SYMMETRIC_KEY_SIZE);
            return true;
        }

        return false;
    }

    bool notNullKeyData() const { return this->getKeyData() != nullptr; }

    void cleanKeyData()
    {
        if (this->notNullKeyData())
        {
            memset(this->getKeyData(), 0, SYMMETRIC_KEY_SIZE);
        }
    }

    void freeKeyData()
    {
        this->cleanKeyData();
        delete this->getKeyData();
        this->setKeyData(nullptr);
    }

public:
    SymmetricKey() : Key(KeySymmetric),
                     keyData(new Byte[SYMMETRIC_KEY_SIZE + 1]) {}

    SymmetricKey(ConstBytes keyData) : Key(KeySymmetric),
                                       keyData(new Byte[SYMMETRIC_KEY_SIZE + 1])
    {
        this->writeKeyData(keyData);
    }

    ~SymmetricKey()
    {
        this->freeKeyData();
    }

    bool setKeyData(ConstBytes keyData, Size keylen, Plaintext passphrase = nullptr) override
    {
        return this->writeKeyData(keyData);
    }

    bool readKeyFile(ConstPlaintext path, Plaintext passphrase = nullptr) override
    {
        return false;
    }

    void reset()
    {
        this->freeKeyData();
    }

    void *getKeyMaterial() override { return this->getKeyData(); }

    static Key *create(const Byte *keyData)
    {
        return new SymmetricKey(keyData);
    }

    static Key *create()
    {
        return new SymmetricKey();
    }
};

#endif
