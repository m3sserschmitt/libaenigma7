#ifndef ASYMMETRIC_KEY_HH
#define ASYMMETRIC_KEY_HH

#include "Key.hh"

#include <openssl/pem.h>
#include <string>

class AsymmetricKey : public Key
{
    EVP_PKEY *key;

    AsymmetricKey(const AsymmetricKey &);
    const AsymmetricKey &operator=(const AsymmetricKey &);

    void init() { this->setPkey(nullptr); }

    const EVP_PKEY *getPkey() const { return this->key; }

    EVP_PKEY *getPkey() { return this->key; }

    void setPkey(EVP_PKEY *key) { this->key = key; }

    void freeKey()
    {
        EVP_PKEY_free(this->getPkey());
        this->setPkey(nullptr);
    }

    bool notNullPkey() const { return this->key != nullptr; }

public:
    AsymmetricKey(KeyType keyType) : Key(keyType) { this->init(); }

    void setKeyType(KeyType keyType) override
    {
        this->freeKey();
        Key::setKeyType(keyType);
    }

    bool setKeyData(ConstBytes keyData, Size len, Plaintext passphrase = nullptr) override;

    bool readKeyFile(ConstPlaintext path, Plaintext passphrase = nullptr) override;

    const void *getKeyMaterial() const override { return this->getPkey(); }

    static Key *create(KeyType keyType)
    {
        return new AsymmetricKey(keyType);
    }
};

#endif
