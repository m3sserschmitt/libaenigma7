#ifndef ASYMMETRIC_KEY_HH
#define ASYMMETRIC_KEY_HH

#include "Key.hh"
#include "File.hh"
#include "CipherContext.hh"

#include <openssl/pem.h>
#include <string>

class AsymmetricKey : public Key
{
    EVP_PKEY *key;

    void init()
    {
        this->setKey(nullptr);
    }

    EVP_PKEY *getKey() { return this->key; }

    void setKey(EVP_PKEY *key) { this->key = key; }

    void freeKey()
    {
        EVP_PKEY_free(this->getKey());
        this->setKey(nullptr);
    }

    bool keyStructureSet() const { return this->key != nullptr; }

public:
    AsymmetricKey() : Key() { this->init(); }

    AsymmetricKey(KeyType keyType) : Key(keyType) { this->init(); }

    /*AsymmetricKey(ConstBase64 key, Plaintext passphrase, KeyType keyType) : Key(keyType)
    {
        this->init();
        this->setKeyData((ConstBytes)key, strlen(key), passphrase);
    }*/

    void setKeyType(KeyType keyType) override
    {
        this->freeKey();
        Key::setKeyType(keyType);
    }

    const EncrypterResult *lock(const EncrypterData *) override;

    const EncrypterResult *unlock(const EncrypterData *) override;

    bool setKeyData(ConstBytes keyData, Size len, Plaintext passphrase = nullptr) override;

    bool readKeyFile(ConstPlaintext path, Plaintext passphrase = nullptr) override;

    static Key *create()
    {
        return new AsymmetricKey();
    }

    static Key *create(KeyType keyType)
    {
        return new AsymmetricKey(keyType);
    }
};

#endif
